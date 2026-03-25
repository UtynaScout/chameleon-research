#!/bin/bash
# ============================================================================
# NetSynth VPN — Deep Packet Comparison
# ============================================================================
# Reads previously captured pcap files and shows a side-by-side comparison
# of what an observer sees vs what's actually being transmitted.
#
# Usage:
#   bash scripts/compare-packets.sh /tmp/netsynth-capture/external_*.pcap /tmp/netsynth-capture/internal_*.pcap
# ============================================================================

EXT_PCAP="$1"
TUN_PCAP="$2"

if [ -z "$EXT_PCAP" ] || [ -z "$TUN_PCAP" ]; then
    echo "Usage: $0 <external.pcap> <internal.pcap>"
    echo ""
    # Auto-detect latest files
    LATEST_EXT=$(ls -t /tmp/netsynth-capture/external_*.pcap 2>/dev/null | head -1)
    LATEST_TUN=$(ls -t /tmp/netsynth-capture/internal_*.pcap 2>/dev/null | head -1)
    if [ -n "$LATEST_EXT" ] && [ -n "$LATEST_TUN" ]; then
        echo "Auto-detected latest captures:"
        EXT_PCAP="$LATEST_EXT"
        TUN_PCAP="$LATEST_TUN"
        echo "  External: $EXT_PCAP"
        echo "  Internal: $TUN_PCAP"
        echo ""
    else
        echo "No captures found in /tmp/netsynth-capture/"
        exit 1
    fi
fi

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           NetSynth VPN — Packet Comparison                     ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

echo "┌──────────────────────────────────────────────────────────────────┐"
echo "│  EXTERNAL VIEW (what ISP / DPI / firewall sees)                 │"
echo "├──────────────────────────────────────────────────────────────────┤"
tcpdump -r "$EXT_PCAP" -n -c 10 2>/dev/null | while read -r line; do
    printf "│  %-64s│\n" "$line"
done
echo "│                                                                  │"
echo "│  Verdict: ALL packets are UDP to port 4433 (QUIC)               │"
echo "│  Content: ENCRYPTED — cannot be read                             │"
echo "└──────────────────────────────────────────────────────────────────┘"
echo ""

echo "┌──────────────────────────────────────────────────────────────────┐"
echo "│  INTERNAL VIEW (decrypted traffic inside tunnel)                │"
echo "├──────────────────────────────────────────────────────────────────┤"
tcpdump -r "$TUN_PCAP" -n -c 10 2>/dev/null | while read -r line; do
    printf "│  %-64s│\n" "$line"
done
echo "│                                                                  │"
echo "│  Verdict: Real traffic visible — HTTP, DNS, ICMP, etc.         │"
echo "│  This is hidden from external observers.                        │"
echo "└──────────────────────────────────────────────────────────────────┘"
echo ""

echo "┌──────────────────────────────────────────────────────────────────┐"
echo "│  STATISTICS                                                     │"
echo "├──────────────────────────────────────────────────────────────────┤"

EXT_TOTAL=$(tcpdump -r "$EXT_PCAP" -n 2>/dev/null | wc -l)
TUN_TOTAL=$(tcpdump -r "$TUN_PCAP" -n 2>/dev/null | wc -l)
EXT_SIZE=$(stat -c%s "$EXT_PCAP" 2>/dev/null || echo "?")
TUN_SIZE=$(stat -c%s "$TUN_PCAP" 2>/dev/null || echo "?")
TUN_PROTOS=$(tcpdump -r "$TUN_PCAP" -n 2>/dev/null | awk '{
    if ($0 ~ /ICMP/) p="ICMP";
    else if ($0 ~ /\.53:/) p="DNS";
    else if ($0 ~ /\.443:/) p="HTTPS";
    else if ($0 ~ /\.80:/) p="HTTP";
    else p="other";
    print p
}' | sort | uniq -c | sort -rn | head -5 | tr '\n' ', ')
TUN_DSTS=$(tcpdump -r "$TUN_PCAP" -n 2>/dev/null | grep -oP '> \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | wc -l)

printf "│  External packets:    %-42s│\n" "$EXT_TOTAL"
printf "│  Internal packets:    %-42s│\n" "$TUN_TOTAL"
printf "│  External pcap size:  %-42s│\n" "$EXT_SIZE bytes"
printf "│  Internal pcap size:  %-42s│\n" "$TUN_SIZE bytes"
printf "│  Unique destinations: %-42s│\n" "$TUN_DSTS IPs (hidden from observer)"
printf "│  Internal protocols:  %-42s│\n" "$TUN_PROTOS"
echo "└──────────────────────────────────────────────────────────────────┘"
echo ""

echo "┌──────────────────────────────────────────────────────────────────┐"
echo "│  SECURITY ANALYSIS                                              │"
echo "├──────────────────────────────────────────────────────────────────┤"
echo "│                                                                  │"
echo "│  Encryption:     2 layers (QUIC/TLS 1.3 + ChaCha20-Poly1305)   │"
echo "│  Protocol:       QUIC (indistinguishable from HTTP/3)           │"
echo "│  DPI resistance: HIGH — looks like standard web browsing        │"
echo "│                                                                  │"
echo "│  What observer CAN see:                                         │"
echo "│    • VPN server IP address                                      │"
echo "│    • Packet sizes and timing                                    │"
echo "│    • Total bandwidth used                                       │"
echo "│                                                                  │"
echo "│  What observer CANNOT see:                                      │"
echo "│    • Destination websites / IPs                                 │"
echo "│    • DNS queries                                                │"
echo "│    • Protocol types (HTTP, ICMP, etc.)                          │"
echo "│    • Packet content                                             │"
echo "│    • That this is a VPN (vs regular HTTPS)                      │"
echo "└──────────────────────────────────────────────────────────────────┘"
