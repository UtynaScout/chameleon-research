#!/usr/bin/env python3
"""
NetSynth — Inter-Arrival Time (IAT) & Timing Analysis
=======================================================
Analyzes packet timing patterns from VPN traffic captures,
computes D_KL divergence against reference distributions,
and detects periodic/shaped patterns.

Usage:
    python3 scripts/timing_analysis.py <pcap_file> [reference.json]

Examples:
    # Capture traffic:
    sudo tshark -i wlp3s0 -c 500 -f "udp port 4433" -w captures/traffic.pcap

    # Analyze:
    python3 scripts/timing_analysis.py captures/traffic.pcap

Prerequisites:
    pip3 install numpy matplotlib
    Optional: pip3 install scipy
"""

import json
import math
import os
import sys
from collections import Counter


def _try_import_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        return None


def kl_divergence(p, q):
    """Compute KL divergence D_KL(P || Q) with Laplace smoothing."""
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

def extract_timestamps_tshark(pcap_file):
    """Extract packet timestamps using tshark."""
    import subprocess

    result = subprocess.run(
        [
            "tshark", "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "udp.length",
            "-e", "ip.src",
            "-e", "ip.dst",
        ],
        capture_output=True, text=True, timeout=60,
    )

    packets = []
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split("\t")
        if len(parts) >= 1 and parts[0]:
            try:
                ts = float(parts[0])
                size = int(parts[1]) if len(parts) > 1 and parts[1] else 0
                src = parts[2] if len(parts) > 2 else ""
                dst = parts[3] if len(parts) > 3 else ""
                packets.append({
                    "timestamp": ts,
                    "size": size,
                    "src": src,
                    "dst": dst,
                })
            except (ValueError, IndexError):
                continue
    return packets


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def compute_iat(packets):
    """Compute inter-arrival times in milliseconds."""
    if len(packets) < 2:
        return []
    timestamps = [p["timestamp"] for p in packets]
    return [(timestamps[i + 1] - timestamps[i]) * 1000.0 for i in range(len(timestamps) - 1)]


def percentile(sorted_data, p):
    """Compute p-th percentile from sorted data."""
    if not sorted_data:
        return 0.0
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    return sorted_data[int(f)] * (c - k) + sorted_data[int(c)] * (k - f)


def analyze_timing(packets, reference_hist=None, num_bins=50):
    """Full timing analysis."""
    if len(packets) < 3:
        return None, None

    iats = compute_iat(packets)
    if not iats:
        return None, None

    sorted_iats = sorted(iats)
    n = len(iats)
    mean_iat = sum(iats) / n
    variance = sum((x - mean_iat) ** 2 for x in iats) / n
    std_iat = math.sqrt(variance)

    # Histogram for D_KL
    min_iat = sorted_iats[0]
    max_iat = sorted_iats[-1]
    # Use log-spaced bins for better resolution at small IATs
    if max_iat > min_iat and max_iat > 0:
        bin_width = (max_iat - min_iat) / num_bins
        if bin_width == 0:
            bin_width = 1
        bins = [min_iat + i * bin_width for i in range(num_bins + 1)]
    else:
        bins = list(range(num_bins + 1))

    hist = [0] * num_bins
    for iat in iats:
        idx = min(int((iat - min_iat) / max(bin_width, 1e-10)), num_bins - 1)
        hist[idx] += 1

    # D_KL
    dkl = None
    if reference_hist is not None:
        ref = reference_hist
        if len(ref) != len(hist):
            ref_resampled = []
            ratio = len(ref) / len(hist)
            for i in range(len(hist)):
                ref_idx = min(int(i * ratio), len(ref) - 1)
                ref_resampled.append(ref[ref_idx])
            ref = ref_resampled
        dkl = kl_divergence(hist, ref)

    # Burst detection: IATs < 1ms
    bursts = sum(1 for iat in iats if iat < 1.0)
    # Idle detection: IATs > 100ms
    idles = sum(1 for iat in iats if iat > 100.0)

    # Periodicity detection (coefficient of variation)
    cv = std_iat / mean_iat if mean_iat > 0 else float("inf")
    # CV < 0.3 suggests periodic/shaped traffic
    # CV > 1.0 suggests bursty/natural traffic

    # Direction-aware analysis
    upstream_iats = []
    downstream_iats = []
    for i in range(len(packets) - 1):
        iat_ms = (packets[i + 1]["timestamp"] - packets[i]["timestamp"]) * 1000
        if packets[i].get("src", "").startswith("10."):
            upstream_iats.append(iat_ms)
        else:
            downstream_iats.append(iat_ms)

    # Capture duration
    duration = packets[-1]["timestamp"] - packets[0]["timestamp"]
    pps = len(packets) / duration if duration > 0 else 0

    stats = {
        "total_packets": len(packets),
        "total_intervals": n,
        "duration_sec": round(duration, 2),
        "packets_per_sec": round(pps, 1),
        "mean_iat_ms": round(mean_iat, 3),
        "std_iat_ms": round(std_iat, 3),
        "min_iat_ms": round(sorted_iats[0], 3),
        "max_iat_ms": round(sorted_iats[-1], 3),
        "p10_iat_ms": round(percentile(sorted_iats, 10), 3),
        "p25_iat_ms": round(percentile(sorted_iats, 25), 3),
        "p50_iat_ms": round(percentile(sorted_iats, 50), 3),
        "p75_iat_ms": round(percentile(sorted_iats, 75), 3),
        "p90_iat_ms": round(percentile(sorted_iats, 90), 3),
        "p95_iat_ms": round(percentile(sorted_iats, 95), 3),
        "p99_iat_ms": round(percentile(sorted_iats, 99), 3),
        "burst_packets_lt_1ms": bursts,
        "idle_packets_gt_100ms": idles,
        "coefficient_of_variation": round(cv, 3),
        "traffic_pattern": (
            "periodic/shaped" if cv < 0.3
            else "moderate" if cv < 1.0
            else "bursty/natural"
        ),
        "upstream_intervals": len(upstream_iats),
        "downstream_intervals": len(downstream_iats),
    }

    if dkl is not None:
        stats["dkl_iat"] = round(dkl, 4)
        stats["dkl_pass"] = dkl < 0.5

    return stats, iats


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

def plot_timing(iats, output_file, stats):
    """Generate timing analysis plots."""
    plt = _try_import_matplotlib()
    if plt is None:
        print("  matplotlib not installed — skipping visualization.")
        return

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))

    # 1. IAT histogram (linear)
    ax = axes[0][0]
    ax.hist(iats, bins=80, color="#FF9800", alpha=0.8, edgecolor="white", linewidth=0.3)
    ax.set_xlabel("Inter-Arrival Time (ms)")
    ax.set_ylabel("Count")
    ax.set_title("IAT Distribution (Linear)")
    ax.axvline(x=stats["mean_iat_ms"], color="red", linestyle="--", alpha=0.7, label=f"Mean={stats['mean_iat_ms']:.1f}ms")
    ax.axvline(x=stats["p50_iat_ms"], color="blue", linestyle="--", alpha=0.7, label=f"P50={stats['p50_iat_ms']:.1f}ms")
    ax.legend(fontsize=8)

    # 2. IAT histogram (log scale)
    ax2 = axes[0][1]
    positive_iats = [x for x in iats if x > 0]
    if positive_iats:
        import numpy as np
        log_bins = np.logspace(
            math.log10(max(min(positive_iats), 0.001)),
            math.log10(max(positive_iats)),
            80,
        )
        ax2.hist(positive_iats, bins=log_bins, color="#9C27B0", alpha=0.8, edgecolor="white", linewidth=0.3)
        ax2.set_xscale("log")
    ax2.set_xlabel("Inter-Arrival Time (ms, log)")
    ax2.set_ylabel("Count")
    ax2.set_title("IAT Distribution (Log Scale)")

    # 3. Time series
    ax3 = axes[1][0]
    ax3.plot(range(len(iats)), iats, color="#2196F3", linewidth=0.5, alpha=0.7)
    ax3.set_xlabel("Packet Index")
    ax3.set_ylabel("IAT (ms)")
    ax3.set_title("IAT Time Series")
    ax3.set_ylim(0, min(stats["p99_iat_ms"] * 1.5, stats["max_iat_ms"]))

    # 4. CDF
    ax4 = axes[1][1]
    sorted_iats = sorted(iats)
    cdf = [(i + 1) / len(sorted_iats) for i in range(len(sorted_iats))]
    ax4.plot(sorted_iats, cdf, color="#4CAF50", linewidth=1.5)
    ax4.set_xlabel("IAT (ms)")
    ax4.set_ylabel("CDF")
    ax4.set_title("IAT Cumulative Distribution")
    ax4.grid(True, alpha=0.3)
    # Mark percentiles
    for p, color in [(50, "blue"), (95, "orange"), (99, "red")]:
        pval = percentile(sorted_iats, p)
        ax4.axvline(x=pval, color=color, linestyle=":", alpha=0.5, label=f"P{p}={pval:.1f}ms")
    ax4.legend(fontsize=8)

    info = (
        f"N={stats['total_packets']}, "
        f"Duration={stats['duration_sec']}s, "
        f"PPS={stats['packets_per_sec']}, "
        f"CV={stats['coefficient_of_variation']:.2f} ({stats['traffic_pattern']})"
    )
    if "dkl_iat" in stats:
        info += f", D_KL={stats['dkl_iat']:.4f}"
    fig.suptitle(info, fontsize=10)

    plt.tight_layout(rect=[0, 0.03, 1, 0.97])
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Plots saved: {output_file}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/timing_analysis.py <pcap_file> [reference.json]")
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
    print("  NetSynth Timing Analysis")
    print("=" * 55)
    print(f"  PCAP:      {pcap_file}")
    print(f"  Reference: {ref_file or '(none)'}")
    print("")

    # Extract
    print("[1/4] Extracting timestamps...")
    packets = extract_timestamps_tshark(pcap_file)
    if not packets:
        print("ERROR: No packets extracted.")
        sys.exit(1)
    print(f"  Extracted {len(packets)} packets")

    # Load reference
    reference_hist = None
    if ref_file and os.path.exists(ref_file):
        print(f"\n[2/4] Loading reference: {ref_file}")
        with open(ref_file) as f:
            ref_data = json.load(f)
            reference_hist = ref_data.get("histogram", ref_data.get("hist"))
        if reference_hist:
            print(f"  Reference bins: {len(reference_hist)}")
    else:
        print("\n[2/4] No reference — skipping D_KL")

    # Analyze
    print("\n[3/4] Computing timing statistics...")
    stats, iats = analyze_timing(packets, reference_hist)

    if stats is None:
        print("ERROR: Not enough data for analysis.")
        sys.exit(1)

    # Print results
    print("\n" + "=" * 55)
    print("  RESULTS")
    print("=" * 55)
    print(json.dumps(stats, indent=2))

    # Assessment
    print("\n--- Traffic Pattern Assessment ---")
    cv = stats["coefficient_of_variation"]
    pattern = stats["traffic_pattern"]
    if pattern == "periodic/shaped":
        print(f"  ✅ Traffic appears SHAPED (CV={cv:.2f} < 0.3)")
        print("     Low variation in inter-arrival times suggests active shaping")
    elif pattern == "moderate":
        print(f"  ⚠️  Traffic is MODERATELY variable (CV={cv:.2f})")
        print("     Some regularity detected, but not strongly shaped")
    else:
        print(f"  ℹ️  Traffic appears NATURAL/BURSTY (CV={cv:.2f} > 1.0)")
        print("     High variation typical of real browsing traffic")

    bursts = stats["burst_packets_lt_1ms"]
    total = stats["total_intervals"]
    if total > 0:
        burst_pct = bursts / total * 100
        print(f"\n  Burst packets (<1ms IAT): {bursts} ({burst_pct:.1f}%)")
        idle = stats["idle_packets_gt_100ms"]
        idle_pct = idle / total * 100
        print(f"  Idle gaps (>100ms IAT):   {idle} ({idle_pct:.1f}%)")

    if "dkl_iat" in stats:
        print(f"\n--- D_KL(IAT) ---")
        status = "✅ PASS" if stats["dkl_pass"] else "❌ FAIL"
        print(f"  D_KL = {stats['dkl_iat']:.4f} (threshold: 0.5) → {status}")

    # Visualization
    print("\n[4/4] Generating visualization...")
    output_png = pcap_file.replace(".pcap", "_timing.png")
    plot_timing(iats, output_png, stats)

    # Save stats
    output_json = pcap_file.replace(".pcap", "_timing.json")
    with open(output_json, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"  Stats saved: {output_json}")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()
