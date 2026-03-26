#!/usr/bin/env python3
"""
NetSynth — Generate Reference Distributions
=============================================
Captures or processes real browser traffic (e.g., Chrome HTTPS/QUIC)
to create reference packet size and IAT distributions for D_KL comparison.

Usage:
    # From existing pcap:
    python3 scripts/generate_reference.py <pcap_file> [output_dir]

    # Example:
    sudo tshark -i wlp3s0 -c 1000 -f "udp port 443" -w captures/chrome_ref.pcap
    python3 scripts/generate_reference.py captures/chrome_ref.pcap data/

Output:
    data/reference_sizes.json  — packet size histogram
    data/reference_iat.json    — inter-arrival time histogram

Prerequisites:
    pip3 install numpy  (optional, for better histograms)
"""

import json
import math
import os
import subprocess
import sys


def extract_from_pcap(pcap_file):
    """Extract sizes and timestamps from pcap via tshark."""
    result = subprocess.run(
        [
            "tshark", "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "udp.length",
        ],
        capture_output=True, text=True, timeout=120,
    )

    timestamps = []
    sizes = []
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            try:
                timestamps.append(float(parts[0]))
                sizes.append(int(parts[1]))
            except ValueError:
                continue

    return timestamps, sizes


def make_histogram(data, num_bins=50):
    """Create a histogram from data."""
    if not data:
        return [], []
    min_val = min(data)
    max_val = max(data)
    bin_width = max(1, (max_val - min_val) / num_bins)
    bins = [min_val + i * bin_width for i in range(num_bins + 1)]
    hist = [0] * num_bins
    for val in data:
        idx = min(int((val - min_val) / bin_width), num_bins - 1)
        hist[idx] += 1
    return hist, [round(b, 4) for b in bins]


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/generate_reference.py <pcap_file> [output_dir]")
        print("")
        print("To capture Chrome QUIC/HTTPS traffic:")
        print("  sudo tshark -i wlp3s0 -c 1000 -f 'udp port 443' -w captures/chrome_ref.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "data"

    if not os.path.exists(pcap_file):
        print(f"ERROR: File not found: {pcap_file}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 50)
    print("  NetSynth Reference Generator")
    print("=" * 50)
    print(f"  Input:  {pcap_file}")
    print(f"  Output: {output_dir}/")
    print("")

    # Extract
    print("[1/3] Extracting data from pcap...")
    timestamps, sizes = extract_from_pcap(pcap_file)
    print(f"  Packets: {len(sizes)}")

    if len(sizes) < 10:
        print("ERROR: Not enough data (need ≥10 packets)")
        sys.exit(1)

    # Sizes
    print("[2/3] Building size reference...")
    size_hist, size_bins = make_histogram(sizes, num_bins=50)
    size_ref = {
        "source": pcap_file,
        "total_packets": len(sizes),
        "histogram": size_hist,
        "bins": size_bins,
        "mean": round(sum(sizes) / len(sizes), 1),
        "min": min(sizes),
        "max": max(sizes),
    }
    size_file = os.path.join(output_dir, "reference_sizes.json")
    with open(size_file, "w") as f:
        json.dump(size_ref, f, indent=2)
    print(f"  Saved: {size_file}")

    # IAT
    print("[3/3] Building IAT reference...")
    iats = [(timestamps[i + 1] - timestamps[i]) * 1000 for i in range(len(timestamps) - 1)]
    iat_hist, iat_bins = make_histogram(iats, num_bins=50)
    iat_ref = {
        "source": pcap_file,
        "total_intervals": len(iats),
        "histogram": iat_hist,
        "bins": iat_bins,
        "mean_ms": round(sum(iats) / len(iats), 3) if iats else 0,
    }
    iat_file = os.path.join(output_dir, "reference_iat.json")
    with open(iat_file, "w") as f:
        json.dump(iat_ref, f, indent=2)
    print(f"  Saved: {iat_file}")

    print("\n" + "=" * 50)
    print("  Reference data ready!")
    print(f"  Use with analysis scripts:")
    print(f"    python3 scripts/packet_size_analysis.py <vpn.pcap> {size_file}")
    print(f"    python3 scripts/timing_analysis.py <vpn.pcap> {iat_file}")
    print("=" * 50)


if __name__ == "__main__":
    main()
