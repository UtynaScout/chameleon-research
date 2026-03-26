#!/bin/bash
# ============================================================================
# NetSynth — Capture QUIC/TLS Handshake for DPI Validation
# ============================================================================
# Captures the initial QUIC connection and extracts TLS ClientHello fields:
#   - SNI (Server Name Indication)
#   - Cipher Suites (for JA3 calculation)
#   - ALPN
#
# Usage (on CLIENT machine):
#   sudo bash scripts/capture-handshake.sh [interface] [port] [vpn_config]
#
# Example:
#   sudo bash scripts/capture-handshake.sh wlp3s0 4433 configs/vpn-client.toml
#
# Prerequisites:
#   sudo apt install tshark
# ============================================================================

set -euo pipefail

INTERFACE="${1:-wlp3s0}"
PORT="${2:-4433}"
VPN_CONFIG="${3:-configs/vpn-client.toml}"
CAPTURE_DIR="captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="${CAPTURE_DIR}/handshake_${TIMESTAMP}.pcap"
REPORT_FILE="${CAPTURE_DIR}/handshake_${TIMESTAMP}.txt"

echo "=============================================="
echo "  NetSynth Handshake Capture"
echo "=============================================="
echo "  Interface:  $INTERFACE"
echo "  Port:       $PORT"
echo "  Config:     $VPN_CONFIG"
echo "  Output:     $PCAP_FILE"
echo "=============================================="

# --- Prerequisites check ---
if ! command -v tshark &>/dev/null; then
    echo "ERROR: tshark not found. Install with: sudo apt install tshark"
    exit 1
fi

if [ ! -f "$VPN_CONFIG" ]; then
    echo "ERROR: VPN config not found: $VPN_CONFIG"
    exit 1
fi

mkdir -p "$CAPTURE_DIR"

# --- Step 1: Stop any running VPN client ---
echo ""
echo "[1/5] Stopping existing VPN client..."
sudo pkill -f "vpn-client" 2>/dev/null || true
sleep 2

# --- Step 2: Start packet capture (pcap for later analysis) ---
echo "[2/5] Starting packet capture on $INTERFACE:$PORT..."
sudo tshark -i "$INTERFACE" -a duration:15 -f "udp port $PORT" \
    -w "$PCAP_FILE" &
TSHARK_PID=$!
sleep 1

# --- Step 3: Start VPN client (triggers new handshake) ---
echo "[3/5] Starting VPN client..."
sudo ./target/release/examples/vpn-client --config "$VPN_CONFIG" &
VPN_PID=$!
sleep 8

# --- Step 4: Stop capture ---
echo "[4/5] Stopping capture..."
sudo kill "$TSHARK_PID" 2>/dev/null || true
wait "$TSHARK_PID" 2>/dev/null || true

# --- Step 5: Analyze captured handshake ---
echo "[5/5] Analyzing handshake..."
echo ""

{
    echo "=============================="
    echo "  Handshake Analysis Report"
    echo "  $(date)"
    echo "=============================="
    echo ""

    echo "--- SNI (Server Name Indication) ---"
    SNI=$(tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" \
        -T fields -e tls.handshake.extensions_server_name 2>/dev/null | head -1)
    if [ -n "$SNI" ]; then
        echo "  SNI: $SNI"
        echo "  Status: CAPTURED"
    else
        echo "  SNI: (empty — QUIC Initial may use different dissection)"
        echo "  Status: CHECK MANUALLY"
        echo "  Trying QUIC-specific extraction..."
        QUIC_SNI=$(tshark -r "$PCAP_FILE" -Y "quic" \
            -T fields -e tls.handshake.extensions_server_name 2>/dev/null | head -1)
        echo "  QUIC SNI: ${QUIC_SNI:-(not found)}"
    fi
    echo ""

    echo "--- Cipher Suites ---"
    tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" \
        -T fields -e tls.handshake.ciphersuite 2>/dev/null | head -5
    echo ""

    echo "--- ALPN ---"
    tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" \
        -T fields -e tls.handshake.extensions_alpn_str 2>/dev/null | head -5
    echo ""

    echo "--- TLS Version ---"
    tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" \
        -T fields -e tls.handshake.version 2>/dev/null | head -5
    echo ""

    echo "--- Supported Groups (EC Curves) ---"
    tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" \
        -T fields -e tls.handshake.extensions.supported_group 2>/dev/null | head -5
    echo ""

    echo "--- All QUIC Initial Packets ---"
    tshark -r "$PCAP_FILE" -Y "quic.long.packet_type == 0" -c 10 2>/dev/null || true
    echo ""

    echo "--- Packet Summary ---"
    TOTAL=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
    echo "  Total packets captured: $TOTAL"
    echo ""

    echo "--- Raw ClientHello (hex, first 200 bytes) ---"
    tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" \
        -T fields -e tls.handshake.type -e tls.handshake.length 2>/dev/null | head -3
    echo ""

} 2>&1 | tee "$REPORT_FILE"

echo ""
echo "=============================================="
echo "  Capture complete!"
echo "  PCAP:   $PCAP_FILE"
echo "  Report: $REPORT_FILE"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  python3 scripts/ja3_analysis.py $PCAP_FILE"
echo ""
echo "VPN client is still running (PID=$VPN_PID)."
echo "To stop: sudo kill $VPN_PID"
