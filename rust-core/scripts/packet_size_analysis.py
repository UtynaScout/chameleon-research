#!/usr/bin/env python3
"""
NetSynth — Packet Size Distribution Analysis
==============================================
Analyzes UDP packet size distribution from VPN traffic captures,
computes D_KL divergence against reference distributions, and generates
histogram visualizations.

Usage:
    python3 scripts/packet_size_analysis.py <pcap_file> [reference_file]

Examples:
    # Capture traffic first:
    sudo tshark -i wlp3s0 -c 500 -f "udp port 4433" -w captures/traffic.pcap

    # Analyze:
    python3 scripts/packet_size_analysis.py captures/traffic.pcap

    # With reference:
    python3 scripts/packet_size_analysis.py captures/traffic.pcap data/reference_sizes.json

Prerequisites:
    pip3 install numpy matplotlib
    Optional: pip3 install scipy  (for D_KL)
"""

import json
import math
import os
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# Minimal numpy-like helpers (fallback if numpy not installed)
# ---------------------------------------------------------------------------

def _try_import_numpy():
    try:
        import numpy as np
        return np
    except ImportError:
        return None


def _try_import_scipy():
    try:
        from scipy.stats import entropy
        return entropy
    except ImportError:
        return None


def _try_import_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        return None


def kl_divergence(p, q):
    """Compute KL divergence D_KL(P || Q) with smoothing."""
    eps = 1e-10
    total_p = sum(p) + eps * len(p)
    total_q = sum(q) + eps * len(q)
    d = 0.0
    for pi, qi in zip(p, q):
        pi_norm = (pi + eps) / total_p
        qi_norm = (qi + eps) / total_q
        d += pi_norm * math.log(pi_norm / qi_norm)
    return d


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_sizes_tshark(pcap_file):
    """Extract UDP payload sizes using tshark CLI."""
    import subprocess

    result = subprocess.run(
        ["tshark", "-r", pcap_file, "-T", "fields", "-e", "udp.length"],
        capture_output=True, text=True, timeout=60,
    )
    sizes = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                sizes.append(int(line))
            except ValueError:
                continue
    return sizes


def extract_sizes_pyshark(pcap_file):
    """Extract UDP payload sizes using pyshark."""
    try:
        import pyshark
    except ImportError:
        return None

    cap = pyshark.FileCapture(pcap_file)
    sizes = []
    for packet in cap:
        try:
            if hasattr(packet, "udp"):
                sizes.append(int(packet.udp.length))
            else:
                sizes.append(int(packet.length))
        except Exception:
            continue
    cap.close()
    return sizes


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_sizes(sizes, reference_hist=None, num_bins=50):
    """Compute statistics and histograms."""
    if not sizes:
        return None, None, None

    np = _try_import_numpy()

    n = len(sizes)
    sorted_sizes = sorted(sizes)
    mean_val = sum(sizes) / n
    variance = sum((x - mean_val) ** 2 for x in sizes) / n
    std_val = math.sqrt(variance)
    min_val = sorted_sizes[0]
    max_val = sorted_sizes[-1]
    median_val = sorted_sizes[n // 2]

    # Histogram
    bin_width = max(1, (max_val - min_val) // num_bins)
    if bin_width == 0:
        bin_width = 1
    bins = list(range(min_val, max_val + bin_width + 1, bin_width))
    hist = [0] * (len(bins) - 1)
    for s in sizes:
        idx = min((s - min_val) // bin_width, len(hist) - 1)
        hist[idx] += 1

    # Counter for top sizes
    counter = Counter(sizes)
    top_sizes = counter.most_common(15)

    # D_KL
    dkl = None
    if reference_hist is not None:
        # Align bins: resample reference to same length
        ref = reference_hist
        if len(ref) != len(hist):
            # Simple resampling: interpolate reference to match hist length
            ref_resampled = []
            ratio = len(ref) / len(hist)
            for i in range(len(hist)):
                ref_idx = min(int(i * ratio), len(ref) - 1)
                ref_resampled.append(ref[ref_idx])
            ref = ref_resampled
        dkl = kl_divergence(hist, ref)

    # MSS clustering detection
    mss_targets = [1200, 1350, 1500]
    mss_tolerance = 80  # ±80 bytes for QUIC/UDP overhead
    mss_clusters = {}
    for target in mss_targets:
        count = sum(1 for s in sizes if abs(s - target) <= mss_tolerance)
        if count > 0:
            mss_clusters[target] = count

    stats = {
        "total_packets": n,
        "mean_size": round(mean_val, 1),
        "std_size": round(std_val, 1),
        "min_size": min_val,
        "max_size": max_val,
        "median_size": median_val,
        "top_15_sizes": [{"size": s, "count": c, "pct": round(c / n * 100, 1)} for s, c in top_sizes],
        "mss_clusters": {str(k): v for k, v in mss_clusters.items()},
        "padding_detected": len(mss_clusters) >= 2,
    }
    if dkl is not None:
        stats["dkl_size"] = round(dkl, 4)
        stats["dkl_pass"] = dkl < 0.5

    return stats, hist, bins


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

def plot_histogram(sizes, hist, bins, output_file, stats):
    """Generate packet size distribution histogram."""
    plt = _try_import_matplotlib()
    if plt is None:
        print("  matplotlib not installed — skipping visualization.")
        print("  Install with: pip3 install matplotlib")
        return

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    # Left: histogram
    ax = axes[0]
    counter = Counter(sizes)
    sorted_unique = sorted(counter.keys())
    counts = [counter[s] for s in sorted_unique]
    ax.bar(sorted_unique, counts, width=max(1, (max(sorted_unique) - min(sorted_unique)) // 100), color="#2196F3", alpha=0.8)
    ax.set_xlabel("UDP Payload Size (bytes)")
    ax.set_ylabel("Packet Count")
    ax.set_title("Packet Size Distribution (VPN Traffic)")

    # Mark MSS targets
    for mss in [1200, 1350, 1500]:
        ax.axvline(x=mss, color="red", linestyle="--", alpha=0.5, label=f"MSS {mss}")
    ax.legend(fontsize=8)

    # Right: CDF
    ax2 = axes[1]
    sorted_sizes = sorted(sizes)
    cdf = [(i + 1) / len(sorted_sizes) for i in range(len(sorted_sizes))]
    ax2.plot(sorted_sizes, cdf, color="#4CAF50", linewidth=1.5)
    ax2.set_xlabel("UDP Payload Size (bytes)")
    ax2.set_ylabel("CDF")
    ax2.set_title("Cumulative Distribution Function")
    ax2.grid(True, alpha=0.3)

    # Stats annotation
    info = (
        f"N={stats['total_packets']}, "
        f"Mean={stats['mean_size']}, "
        f"Std={stats['std_size']}, "
        f"Padding={'Yes' if stats.get('padding_detected') else 'No'}"
    )
    if "dkl_size" in stats:
        info += f", D_KL={stats['dkl_size']:.4f}"
    fig.suptitle(info, fontsize=10, y=0.02)

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Histogram saved: {output_file}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/packet_size_analysis.py <pcap_file> [reference.json]")
        print("")
        print("Capture traffic first:")
        print("  sudo tshark -i wlp3s0 -c 500 -f 'udp port 4433' -w captures/traffic.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]
    ref_file = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(pcap_file):
        print(f"ERROR: File not found: {pcap_file}")
        sys.exit(1)

    print("=" * 55)
    print("  NetSynth Packet Size Analysis")
    print("=" * 55)
    print(f"  PCAP:      {pcap_file}")
    print(f"  Reference: {ref_file or '(none)'}")
    print("")

    # Extract sizes
    print("[1/4] Extracting packet sizes...")
    sizes = extract_sizes_tshark(pcap_file)
    if not sizes:
        print("  tshark extraction returned no data, trying pyshark...")
        sizes = extract_sizes_pyshark(pcap_file)

    if not sizes:
        print("ERROR: No packet sizes extracted.")
        sys.exit(1)

    print(f"  Extracted {len(sizes)} packets")

    # Load reference if provided
    reference_hist = None
    if ref_file and os.path.exists(ref_file):
        print(f"\n[2/4] Loading reference: {ref_file}")
        with open(ref_file) as f:
            ref_data = json.load(f)
            reference_hist = ref_data.get("histogram", ref_data.get("hist"))
        if reference_hist:
            print(f"  Reference bins: {len(reference_hist)}")
    else:
        print("\n[2/4] No reference file — skipping D_KL calculation")

    # Analyze
    print("\n[3/4] Computing statistics...")
    stats, hist, bins = analyze_sizes(sizes, reference_hist)

    if stats is None:
        print("ERROR: Analysis failed.")
        sys.exit(1)

    # Print results
    print("\n" + "=" * 55)
    print("  RESULTS")
    print("=" * 55)
    print(json.dumps(stats, indent=2))

    # Padding assessment
    print("\n--- Padding Assessment ---")
    if stats.get("padding_detected"):
        print("  ✅ MSS padding DETECTED")
        for target, count in stats["mss_clusters"].items():
            pct = count / stats["total_packets"] * 100
            print(f"     MSS ~{target}: {count} packets ({pct:.1f}%)")
    else:
        print("  ⚠️  MSS padding NOT detected (sizes may not cluster around targets)")

    if "dkl_size" in stats:
        print(f"\n--- D_KL(Size) ---")
        status = "✅ PASS" if stats["dkl_pass"] else "❌ FAIL"
        print(f"  D_KL = {stats['dkl_size']:.4f} (threshold: 0.5) → {status}")

    # Visualization
    print("\n[4/4] Generating visualization...")
    output_png = pcap_file.replace(".pcap", "_sizes.png")
    plot_histogram(sizes, hist, bins, output_png, stats)

    # Save stats
    output_json = pcap_file.replace(".pcap", "_sizes.json")
    with open(output_json, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"  Stats saved: {output_json}")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()
