#!/usr/bin/env python3
"""
NetSynth — JA3 Fingerprint Analysis
=====================================
Extracts JA3 fingerprint from a QUIC/TLS pcap and compares it with
known browser fingerprints.

Usage:
    python3 scripts/ja3_analysis.py captures/handshake_XXXX.pcap

Prerequisites:
    pip3 install pyshark

Notes:
    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
    For QUIC, the TLS version in JA3 is typically 0x0303 (TLS 1.2 compat)
    since QUIC always uses TLS 1.3 but the record-layer version field
    may show 1.2-compatible values.
"""

import hashlib
import json
import sys
import os

# Known JA3 hashes for reference (from ja3er.com and research databases)
# These are approximate — JA3 varies by OS/build/extensions.
KNOWN_FINGERPRINTS = {
    "chrome_130_tls13": {
        "description": "Google Chrome 130 (TLS 1.3, typical)",
        "hash": None,  # Will be populated from capture
        "ciphers_expected": "4865,4866,4867",  # TLS_AES_128_GCM, AES_256_GCM, CHACHA20
    },
    "firefox_120_tls13": {
        "description": "Mozilla Firefox 120 (TLS 1.3, typical)",
        "hash": None,
        "ciphers_expected": "4865,4867,4866",  # AES_128, CHACHA20, AES_256
    },
    "rustls_default": {
        "description": "Rustls default (ring provider)",
        "hash": None,
        "ciphers_expected": "4865,4866,4867",
    },
}


def extract_ja3_from_pyshark(pcap_file):
    """Extract JA3 components using pyshark."""
    try:
        import pyshark
    except ImportError:
        print("ERROR: pyshark not installed. Run: pip3 install pyshark")
        sys.exit(1)

    results = []

    # Try both TLS and QUIC dissection
    for display_filter in [
        "tls.handshake.type == 1",
        "quic && tls.handshake.type == 1",
    ]:
        try:
            cap = pyshark.FileCapture(
                pcap_file,
                display_filter=display_filter,
                use_json=True,
                include_raw=True,
            )
        except Exception:
            cap = pyshark.FileCapture(pcap_file, display_filter=display_filter)

        for packet in cap:
            try:
                result = _extract_from_packet(packet)
                if result:
                    results.append(result)
            except Exception as e:
                print(f"  Warning: Could not parse packet: {e}")
                continue

        cap.close()

        if results:
            break

    return results


def _extract_from_packet(packet):
    """Extract JA3 fields from a single pyshark packet."""
    tls_layer = None
    for layer in packet.layers:
        if layer.layer_name == "tls":
            tls_layer = layer
            break

    if not tls_layer:
        return None

    # TLS Version (handshake version, not record version)
    version = _get_field(tls_layer, [
        "handshake_version",
        "tls.handshake.version",
    ])

    # Cipher suites
    ciphers_raw = _get_field(tls_layer, [
        "handshake_ciphersuite",
        "tls.handshake.ciphersuite",
    ])

    # Extensions
    extensions_raw = _get_field(tls_layer, [
        "handshake_extension_type",
        "tls.handshake.extension.type",
        "handshake_extensions_type",
    ])

    # Elliptic curves / supported groups
    curves_raw = _get_field(tls_layer, [
        "handshake_extensions_supported_group",
        "tls.handshake.extensions.supported_group",
        "handshake_extensions_elliptic_curves",
    ])

    # EC point formats
    points_raw = _get_field(tls_layer, [
        "handshake_extensions_ec_point_formats",
        "tls.handshake.extensions.ec_point_formats",
        "handshake_extensions_ec_point_format",
    ])

    # SNI
    sni = _get_field(tls_layer, [
        "handshake_extensions_server_name",
        "tls.handshake.extensions_server_name",
    ])

    # ALPN
    alpn = _get_field(tls_layer, [
        "handshake_extensions_alpn_str",
        "tls.handshake.extensions_alpn_str",
    ])

    # Build JA3 string
    version_str = _normalize_version(version)
    ciphers_str = _normalize_list(ciphers_raw)
    extensions_str = _normalize_list(extensions_raw)
    curves_str = _normalize_list(curves_raw)
    points_str = _normalize_list(points_raw)

    # Filter GREASE values from JA3 (0x_a_a pattern)
    ciphers_str = _remove_grease(ciphers_str)
    extensions_str = _remove_grease(extensions_str)
    curves_str = _remove_grease(curves_str)

    ja3_string = f"{version_str},{ciphers_str},{extensions_str},{curves_str},{points_str}"
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

    return {
        "ja3_string": ja3_string,
        "ja3_hash": ja3_hash,
        "version": version_str,
        "ciphers": ciphers_str,
        "extensions": extensions_str,
        "curves": curves_str,
        "points": points_str,
        "sni": sni or "",
        "alpn": alpn or "",
    }


def _get_field(layer, field_names):
    """Try multiple field names and return the first that works."""
    for name in field_names:
        try:
            val = getattr(layer, name.replace(".", "_"), None)
            if val is None:
                val = layer.get_field(name)
            if val is not None:
                return str(val)
        except Exception:
            continue
    return ""


def _normalize_version(version_str):
    """Normalize TLS version to decimal."""
    if not version_str:
        return "771"  # TLS 1.2 default for JA3
    version_str = version_str.strip()
    if version_str.startswith("0x"):
        return str(int(version_str, 16))
    try:
        return str(int(version_str))
    except ValueError:
        return version_str


def _normalize_list(raw):
    """Normalize comma/dash-separated hex or decimal values."""
    if not raw:
        return ""
    # pyshark may return values separated by commas or as repeated fields
    items = []
    for part in str(raw).replace(",", "-").split("-"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("0x"):
            items.append(str(int(part, 16)))
        else:
            try:
                items.append(str(int(part)))
            except ValueError:
                items.append(part)
    return "-".join(items)


def _remove_grease(value_str):
    """Remove GREASE values (0x_a_a pattern) from JA3 components."""
    if not value_str:
        return ""
    grease_values = {
        "2570", "6682", "10794", "14906", "19018", "23130",
        "27242", "31354", "35466", "39578", "43690", "47802",
        "51914", "56026", "60138", "64250",
    }
    items = [v for v in value_str.split("-") if v not in grease_values]
    return "-".join(items)


def compare_fingerprints(result):
    """Compare extracted JA3 with known fingerprints."""
    print("\n--- Fingerprint Comparison ---")

    extracted_ciphers = result["ciphers"].replace("-", ",")

    matches = []
    for name, known in KNOWN_FINGERPRINTS.items():
        if known.get("hash") and result["ja3_hash"] == known["hash"]:
            matches.append((name, "EXACT HASH MATCH"))
            continue

        expected = known.get("ciphers_expected", "")
        if expected and extracted_ciphers == expected:
            matches.append((name, "CIPHER ORDER MATCH"))

    if matches:
        for name, match_type in matches:
            desc = KNOWN_FINGERPRINTS[name]["description"]
            print(f"  ✅ {match_type}: {desc}")
    else:
        print("  ⚠️  No exact match with known fingerprints")
        print("  This may indicate a unique fingerprint (check cipher order)")

    # Show side-by-side cipher comparison
    print("\n--- Cipher Suite Comparison ---")
    print(f"  Captured: {extracted_ciphers}")
    for name, known in KNOWN_FINGERPRINTS.items():
        expected = known.get("ciphers_expected", "?")
        match = "✅" if extracted_ciphers == expected else "❌"
        print(f"  {match} {name}: {expected}")


def fallback_tshark_analysis(pcap_file):
    """Fallback: use tshark CLI directly if pyshark fails."""
    import subprocess

    print("\n--- Fallback: tshark CLI analysis ---")

    fields = {
        "SNI": "tls.handshake.extensions_server_name",
        "Cipher Suites": "tls.handshake.ciphersuite",
        "ALPN": "tls.handshake.extensions_alpn_str",
        "TLS Version": "tls.handshake.version",
        "Supported Groups": "tls.handshake.extensions.supported_group",
        "EC Point Formats": "tls.handshake.extensions.ec_point_formats",
    }

    results = {}
    for label, field in fields.items():
        try:
            out = subprocess.run(
                [
                    "tshark", "-r", pcap_file,
                    "-Y", "tls.handshake.type == 1",
                    "-T", "fields", "-e", field,
                ],
                capture_output=True, text=True, timeout=10,
            )
            value = out.stdout.strip()
            results[label] = value if value else "(empty)"
            print(f"  {label}: {value if value else '(empty)'}")
        except Exception as e:
            print(f"  {label}: ERROR ({e})")

    # Build JA3 from tshark fields
    version = results.get("TLS Version", "")
    ciphers = results.get("Cipher Suites", "")
    groups = results.get("Supported Groups", "")
    points = results.get("EC Point Formats", "")

    if ciphers:
        # tshark returns ciphers as comma-separated hex or decimal
        ciphers_clean = ciphers.replace(",", "-").replace("\t", "-")
        print(f"\n  Raw JA3 ciphers: {ciphers_clean}")

    return results


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/ja3_analysis.py <pcap_file>")
        print("Example: python3 scripts/ja3_analysis.py captures/handshake_20260326.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(f"ERROR: File not found: {pcap_file}")
        sys.exit(1)

    print("=" * 50)
    print("  NetSynth JA3 Fingerprint Analysis")
    print("=" * 50)
    print(f"  Input: {pcap_file}")
    print("")

    # Try pyshark first
    results = []
    try:
        results = extract_ja3_from_pyshark(pcap_file)
    except Exception as e:
        print(f"  pyshark extraction failed: {e}")
        print("  Falling back to tshark CLI...")

    if results:
        for i, result in enumerate(results):
            print(f"\n--- ClientHello #{i+1} ---")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            compare_fingerprints(result)

        # Save results
        output_file = pcap_file.replace(".pcap", "_ja3.json")
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n  Results saved: {output_file}")
    else:
        print("\n  No ClientHello found via pyshark.")
        fallback_tshark_analysis(pcap_file)

    print("\n" + "=" * 50)


if __name__ == "__main__":
    main()
