from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, UDP, PcapReader


def extract_stats_from_pcap(pcap_path: Path) -> dict[str, Any]:
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    packet_sizes: list[int] = []
    timestamps: list[float] = []
    up_count = 0

    with PcapReader(str(pcap_path)) as packets:
        for pkt in packets:
            if IP not in pkt:
                continue

            size = int(len(pkt))
            ts = float(pkt.time)
            packet_sizes.append(size)
            timestamps.append(ts)

            if TCP in pkt or UDP in pkt:
                src = str(pkt[IP].src)
                dst = str(pkt[IP].dst)
                if src < dst:
                    up_count += 1

    if len(timestamps) < 2:
        iat_ms: list[float] = []
    else:
        iat_ms = [max(0.0, (timestamps[i] - timestamps[i - 1]) * 1000.0) for i in range(1, len(timestamps))]

    total = max(len(packet_sizes), 1)
    return {
        "packet_sizes": packet_sizes,
        "iat_ms": iat_ms,
        "up_ratio": up_count / total,
        "packet_count": len(packet_sizes),
    }


def save_stats(stats: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Extract traffic stats from PCAP")
    parser.add_argument("pcap", type=Path, help="Path to source pcap")
    parser.add_argument("--out", type=Path, default=Path("data/reference_stats.json"))
    args = parser.parse_args()

    result = extract_stats_from_pcap(args.pcap)
    save_stats(result, args.out)
    print(f"Saved stats to {args.out}")
