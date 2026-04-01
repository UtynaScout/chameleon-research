#!/bin/bash
# ============================================================================
# NetSynth — Full DPI Validation (run as root)
# Usage: sudo bash scripts/validate-all.sh
# ============================================================================

INTERFACE="wlp3s0"
PORT="4433"
CONFIG="configs/vpn-client.toml"
VENV="/home/user/venv"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$DIR"
mkdir -p captures
chmod 777 captures
rm -f captures/handshake.pcap captures/traffic.pcap

echo "=============================================="
echo "  NetSynth DPI Validation"
echo "  Dir: $DIR"
echo "=============================================="

# --- Kill old processes ---
echo ""
echo "[0/9] Cleaning up old processes..."
pkill -f vpn-client 2>/dev/null || true
pkill tshark 2>/dev/null || true
sleep 2
# Clean stale routes from previous VPN runs
ip route del 77.110.97.128/32 2>/dev/null || true
ip route del default dev tun0 2>/dev/null || true

# --- Step 1-3: Capture handshake ---
HSHAKE_TMP="/tmp/netsynth_handshake.pcap"
TRAFFIC_TMP="/tmp/netsynth_traffic.pcap"
rm -f "$HSHAKE_TMP" "$TRAFFIC_TMP"

echo ""
echo "[1/9] Starting tshark for handshake capture (20 sec)..."
tshark -i "$INTERFACE" -a duration:20 -f "udp port $PORT" -w "$HSHAKE_TMP" 2>&1 &
TSHARK_PID=$!
sleep 2

echo "[2/9] Starting VPN client..."
./target/release/examples/vpn-client --config "$CONFIG" &
VPN_PID=$!

echo "[3/9] Waiting 15 seconds for handshake + connection..."
sleep 15

# Stop tshark (it should auto-stop at 20s, but just in case)
kill $TSHARK_PID 2>/dev/null || true
wait $TSHARK_PID 2>/dev/null || true

# Copy from /tmp to captures/
cp "$HSHAKE_TMP" captures/handshake.pcap 2>/dev/null || true

# --- Step 4: Check file ---
echo ""
echo "[4/9] Checking handshake capture..."
ls -la captures/handshake.pcap "$HSHAKE_TMP" 2>/dev/null
echo ""

# --- Step 5: Extract SNI + Ciphers ---
echo "[5/9] SNI + Ciphers + ALPN:"
echo "--- SNI ---"
tshark -r captures/handshake.pcap -Y "tls.handshake.type == 1" \
    -T fields -e tls.handshake.extensions_server_name 2>/dev/null || echo "(empty)"
echo ""
echo "--- Cipher Suites ---"
tshark -r captures/handshake.pcap -Y "tls.handshake.type == 1" \
    -T fields -e tls.handshake.ciphersuite 2>/dev/null || echo "(empty)"
echo ""
echo "--- ALPN ---"
tshark -r captures/handshake.pcap -Y "tls.handshake.type == 1" \
    -T fields -e tls.handshake.extensions_alpn_str 2>/dev/null || echo "(empty)"
echo ""
echo "--- TLS Version ---"
tshark -r captures/handshake.pcap -Y "tls.handshake.type == 1" \
    -T fields -e tls.handshake.version 2>/dev/null || echo "(empty)"
echo ""
echo "--- QUIC packets total ---"
tshark -r captures/handshake.pcap 2>/dev/null | wc -l
echo ""

# --- Step 6: JA3 ---
echo "[6/9] JA3 Analysis..."
"$VENV/bin/python3" scripts/ja3_analysis.py captures/handshake.pcap 2>&1
echo ""

# --- Step 7: Capture bulk traffic ---
echo "[7/9] Checking VPN client is alive..."
if ! kill -0 $VPN_PID 2>/dev/null; then
    echo "     VPN client died, restarting..."
    ./target/release/examples/vpn-client --config "$CONFIG" &
    VPN_PID=$!
    sleep 5
fi

# Verify connectivity
echo "     Testing connectivity..."
ping -c 2 8.8.8.8 -W 3 > /dev/null 2>&1 && echo "     Connectivity OK" || echo "     WARNING: no connectivity"

echo "[7/9] Capturing 500 packets of VPN traffic..."
echo "     Generating load in background..."

# Generate traffic in background
(
    sleep 2
    ping -c 30 8.8.8.8 > /dev/null 2>&1
    curl -s https://example.com > /dev/null 2>&1
    curl -s https://www.google.com > /dev/null 2>&1
    curl -s https://ya.ru > /dev/null 2>&1
    curl -s https://wikipedia.org > /dev/null 2>&1
    ping -c 30 1.1.1.1 > /dev/null 2>&1
    curl -s https://github.com > /dev/null 2>&1
    curl -s https://httpbin.org/get > /dev/null 2>&1
    ping -c 30 8.8.4.4 > /dev/null 2>&1
) &
LOAD_PID=$!

tshark -i "$INTERFACE" -c 500 -f "udp port $PORT" -w "$TRAFFIC_TMP" 2>&1
kill $LOAD_PID 2>/dev/null || true
wait $LOAD_PID 2>/dev/null || true
cp "$TRAFFIC_TMP" captures/traffic.pcap 2>/dev/null || true

echo "     Captured: $(tshark -r captures/traffic.pcap 2>/dev/null | wc -l) packets"
echo ""

# --- Step 8: Packet size analysis ---
echo "[8/9] Packet Size Analysis..."
"$VENV/bin/python3" scripts/packet_size_analysis.py captures/traffic.pcap 2>&1
echo ""

# --- Step 9: Timing analysis ---
echo "[9/9] Timing Analysis..."
"$VENV/bin/python3" scripts/timing_analysis.py captures/traffic.pcap 2>&1
echo ""

echo "=============================================="
echo "  DONE! VPN client still running (PID=$VPN_PID)"
echo "  To stop: sudo kill $VPN_PID"
echo "=============================================="
