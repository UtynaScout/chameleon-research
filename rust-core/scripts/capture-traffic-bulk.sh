#!/bin/bash
# ============================================================================
# NetSynth — Capture Bulk VPN Traffic for Size/Timing Analysis
# ============================================================================
# Captures N packets of VPN traffic while you generate load (browsing, curl,
# pings, etc). Outputs pcap for use with packet_size_analysis.py and
# timing_analysis.py.
#
# Usage:
#   sudo bash scripts/capture-traffic-bulk.sh [interface] [port] [packets]
#
# Example:
#   sudo bash scripts/capture-traffic-bulk.sh wlp3s0 4433 500
# ============================================================================

set -euo pipefail

INTERFACE="${1:-wlp3s0}"
PORT="${2:-4433}"
PACKETS="${3:-500}"
CAPTURE_DIR="captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="${CAPTURE_DIR}/traffic_${TIMESTAMP}.pcap"

mkdir -p "$CAPTURE_DIR"

echo "=============================================="
echo "  NetSynth Bulk Traffic Capture"
echo "=============================================="
echo "  Interface: $INTERFACE"
echo "  Port:      $PORT"
echo "  Packets:   $PACKETS"
echo "  Output:    $PCAP_FILE"
echo "=============================================="
echo ""
echo "  Generate traffic while capturing:"
echo "    ping -c 20 8.8.8.8"
echo "    curl -s https://example.com"
echo "    curl -s https://www.google.com"
echo "    wget -q -O /dev/null https://speed.hetzner.de/100MB.bin &"
echo ""

sudo tshark -i "$INTERFACE" -c "$PACKETS" -f "udp port $PORT" -w "$PCAP_FILE"

echo ""
echo "=============================================="
echo "  Capture complete: $PCAP_FILE"
echo "=============================================="
echo ""
echo "  Next steps:"
echo "    python3 scripts/packet_size_analysis.py $PCAP_FILE"
echo "    python3 scripts/timing_analysis.py $PCAP_FILE"
