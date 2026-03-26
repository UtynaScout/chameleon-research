//! DPI resistance tests (Phase 6).
//!
//! These tests verify that the DPI resistance features work correctly:
//! - TLS fingerprint presets produce distinct cipher suite orderings
//! - Packet padding correctly pads and unpads data
//! - Padded VPN tunnel roundtrips work end-to-end
//! - Traffic shaping profiles are well-formed
//!
//! **Note:** These tests do not require root, TUN devices, or network
//! access. They run on any platform via loopback QUIC connections.

use std::net::SocketAddr;

use chameleon_core::crypto::derive_session_key;
use chameleon_core::transport::dpi::{
    DpiProfile, FingerprintPreset, PaddingConfig, PaddingMode, ShapingProfile,
};
use chameleon_core::transport::quic::QuicTransport;
use chameleon_core::transport::TransportConfig;
use chameleon_core::tun::VpnTunnel;

// =========================================================================
// 1. TLS Fingerprint Tests
// =========================================================================

#[test]
fn test_chrome_cipher_suite_order() {
    let provider = FingerprintPreset::Chrome130.crypto_provider();
    let ids: Vec<u16> = provider
        .cipher_suites
        .iter()
        .map(|cs| u16::from(cs.suite()))
        .collect();

    // Chrome 130 puts AES-128-GCM first (0x1301), not AES-256-GCM (0x1302)
    assert_eq!(ids[0], 0x1301, "Chrome should put AES-128-GCM first");
    assert_eq!(ids[1], 0x1302, "Chrome should put AES-256-GCM second");
    assert_eq!(ids[2], 0x1303, "Chrome should put CHACHA20 third");

    // Verify all 9 cipher suites are present
    assert_eq!(ids.len(), 9);
    assert_eq!(ids, FingerprintPreset::Chrome130.expected_cipher_ids());
}

#[test]
fn test_firefox_cipher_suite_order() {
    let provider = FingerprintPreset::Firefox120.crypto_provider();
    let ids: Vec<u16> = provider
        .cipher_suites
        .iter()
        .map(|cs| u16::from(cs.suite()))
        .collect();

    // Firefox 120 puts ChaCha before AES-256-GCM in TLS 1.3
    assert_eq!(ids[0], 0x1301, "Firefox puts AES-128-GCM first");
    assert_eq!(ids[1], 0x1303, "Firefox puts CHACHA20 second");
    assert_eq!(ids[2], 0x1302, "Firefox puts AES-256-GCM third");

    assert_eq!(ids.len(), 9);
    assert_eq!(ids, FingerprintPreset::Firefox120.expected_cipher_ids());
}

#[test]
fn test_rustls_default_cipher_suite_order() {
    let provider = FingerprintPreset::RustlsDefault.crypto_provider();
    let ids: Vec<u16> = provider
        .cipher_suites
        .iter()
        .map(|cs| u16::from(cs.suite()))
        .collect();

    // rustls default puts AES-256-GCM first
    assert_eq!(ids[0], 0x1302, "rustls puts AES-256-GCM first");
    assert_eq!(ids, FingerprintPreset::RustlsDefault.expected_cipher_ids());
}

#[test]
fn test_all_presets_are_distinct() {
    let chrome = FingerprintPreset::Chrome130.expected_cipher_ids();
    let firefox = FingerprintPreset::Firefox120.expected_cipher_ids();
    let rustls_ids = FingerprintPreset::RustlsDefault.expected_cipher_ids();

    assert_ne!(chrome, firefox, "Chrome and Firefox must differ");
    assert_ne!(chrome, rustls_ids, "Chrome and rustls must differ");
    assert_ne!(firefox, rustls_ids, "Firefox and rustls must differ");
}

#[test]
fn test_all_presets_have_same_cipher_set() {
    // All presets should contain the same cipher suites, just in different order
    let mut chrome = FingerprintPreset::Chrome130.expected_cipher_ids();
    let mut firefox = FingerprintPreset::Firefox120.expected_cipher_ids();
    let mut rustls_ids = FingerprintPreset::RustlsDefault.expected_cipher_ids();

    chrome.sort();
    firefox.sort();
    rustls_ids.sort();

    assert_eq!(chrome, firefox, "Same ciphers, different order");
    assert_eq!(chrome, rustls_ids, "Same ciphers, different order");
}

// =========================================================================
// 2. SNI / ALPN Configuration Tests
// =========================================================================

#[test]
fn test_dpi_profile_default_has_no_sni() {
    let profile = DpiProfile::default();
    assert!(profile.sni.is_none(), "Default profile should have no SNI override");
    assert_eq!(profile.alpn, vec!["h3"]);
}

#[test]
fn test_dpi_profile_with_custom_sni() {
    let profile = DpiProfile {
        sni: Some("www.google.com".into()),
        alpn: vec!["h3".into()],
        fingerprint: FingerprintPreset::Chrome130,
        ..DpiProfile::default()
    };
    assert_eq!(profile.sni.as_deref(), Some("www.google.com"));
}

#[test]
fn test_dpi_profile_with_custom_alpn() {
    let profile = DpiProfile {
        alpn: vec!["h3".into(), "h2".into()],
        ..DpiProfile::default()
    };
    assert_eq!(profile.alpn, vec!["h3", "h2"]);
}

// =========================================================================
// 3. Packet Padding Tests
// =========================================================================

#[test]
fn test_padding_disabled_preserves_data() {
    let cfg = PaddingConfig {
        enabled: false,
        mode: PaddingMode::None,
    };
    let data = b"original packet data";
    let padded = cfg.pad_packet(data);
    // Still gets 2-byte header even when disabled (for protocol uniformity)
    assert_eq!(padded.len(), 2 + data.len());
    let unpadded = PaddingConfig::unpad_packet(&padded).unwrap();
    assert_eq!(unpadded, data);
}

#[test]
fn test_padding_mss_reaches_target() {
    let cfg = PaddingConfig {
        enabled: true,
        mode: PaddingMode::Mss(vec![128, 256, 512, 1024, 1200]),
    };

    // Small packet (10 bytes + 2 header = 12) → pad to 128
    let padded = cfg.pad_packet(&[0x42; 10]);
    assert_eq!(padded.len(), 128);

    // Medium packet (200 bytes + 2 header = 202) → pad to 256
    let padded = cfg.pad_packet(&[0x42; 200]);
    assert_eq!(padded.len(), 256);

    // Large packet (1000 bytes + 2 header = 1002) → pad to 1024
    let padded = cfg.pad_packet(&[0x42; 1000]);
    assert_eq!(padded.len(), 1024);
}

#[test]
fn test_padding_fixed_size() {
    let cfg = PaddingConfig {
        enabled: true,
        mode: PaddingMode::Fixed(500),
    };
    let padded = cfg.pad_packet(&[1, 2, 3, 4, 5]);
    assert_eq!(padded.len(), 500);
    let unpadded = PaddingConfig::unpad_packet(&padded).unwrap();
    assert_eq!(unpadded, vec![1, 2, 3, 4, 5]);
}

#[test]
fn test_padding_random_range() {
    let cfg = PaddingConfig {
        enabled: true,
        mode: PaddingMode::Random {
            min_size: 100,
            max_size: 500,
        },
    };
    let padded = cfg.pad_packet(&[0xAA; 20]);
    assert!(padded.len() >= 100, "size {} should be >= 100", padded.len());
    assert!(padded.len() <= 500, "size {} should be <= 500", padded.len());
}

#[test]
fn test_padding_does_not_truncate_large_packets() {
    let cfg = PaddingConfig {
        enabled: true,
        mode: PaddingMode::Fixed(100),
    };
    // Data larger than target: should not truncate
    let data = vec![0x55; 200];
    let padded = cfg.pad_packet(&data);
    assert!(padded.len() >= 202, "must not truncate large packets");
    let unpadded = PaddingConfig::unpad_packet(&padded).unwrap();
    assert_eq!(unpadded, data);
}

#[test]
fn test_padding_dummy_packet_discarded() {
    let cfg = PaddingConfig {
        enabled: true,
        mode: PaddingMode::Fixed(128),
    };
    let dummy = cfg.dummy_packet(128);
    assert_eq!(dummy.len(), 128);
    // original_len should be 0
    assert_eq!(u16::from_be_bytes([dummy[0], dummy[1]]), 0);
    // unpad should return None (dummy)
    assert!(PaddingConfig::unpad_packet(&dummy).is_none());
}

#[test]
fn test_padding_size_distribution_uniform() {
    // With MSS padding, all packets should end up at one of the MSS values
    let cfg = PaddingConfig {
        enabled: true,
        mode: PaddingMode::Mss(vec![128, 256, 512, 1024, 1350]),
    };

    let sizes: Vec<usize> = (1..=100)
        .map(|i| {
            let data = vec![0u8; i * 10]; // 10, 20, ..., 1000 bytes
            cfg.pad_packet(&data).len()
        })
        .collect();

    // All sizes should be one of the MSS values
    let valid_sizes = [128, 256, 512, 1024, 1350];
    for size in &sizes {
        assert!(
            valid_sizes.contains(size) || *size > *valid_sizes.last().unwrap(),
            "size {} should be one of {:?}",
            size,
            valid_sizes
        );
    }

    // No peaks at 84, 152, etc. (the original fingerprint-able sizes)
    let has_original_peaks = sizes.iter().any(|&s| s == 84 || s == 152 || s == 81);
    assert!(!has_original_peaks, "should not have original fingerprintable sizes");
}

// =========================================================================
// 4. VPN Tunnel with Padding (End-to-End)
// =========================================================================

async fn setup_server() -> (quinn::Endpoint, SocketAddr) {
    let (ep, _cert) = QuicTransport::bind_server("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind_server");
    let addr = ep.local_addr().unwrap();
    (ep, addr)
}

async fn connect_client(addr: SocketAddr) -> quinn::Connection {
    let mut t = QuicTransport::new(TransportConfig::default());
    t.bind_client().await.unwrap();
    t.connect(addr, "localhost").await.unwrap();
    t.connection().unwrap().clone()
}

#[tokio::test]
async fn test_padded_tunnel_roundtrip() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = derive_session_key(b"test-psk", b"salt", b"dpi-pad-test");

    let padding = PaddingConfig {
        enabled: true,
        mode: PaddingMode::Fixed(256),
    };

    let (ep, addr) = setup_server().await;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let server_key = key;
    let server_padding = padding.clone();
    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();

        let mut tunnel = VpnTunnel::server(&conn, server_key).await.unwrap();
        tunnel.set_padding(server_padding);
        let (mut tx, mut rx) = tunnel.split();

        let pkt = rx.recv_packet().await.unwrap();
        assert_eq!(pkt, b"padded hello");

        tx.send_packet(b"padded reply").await.unwrap();
        let _ = done_rx.await;
    });

    let conn = connect_client(addr).await;
    let mut tunnel = VpnTunnel::client(&conn, key).await.unwrap();
    tunnel.set_padding(padding);
    let (mut tx, mut rx) = tunnel.split();

    tx.send_packet(b"padded hello").await.unwrap();
    let reply = rx.recv_packet().await.unwrap();
    assert_eq!(reply, b"padded reply");

    let _ = done_tx.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn test_padded_tunnel_many_packets() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = derive_session_key(b"test-psk", b"salt", b"dpi-pad-many");

    let padding = PaddingConfig {
        enabled: true,
        mode: PaddingMode::Mss(vec![128, 256, 512, 1024, 1350]),
    };

    let (ep, addr) = setup_server().await;
    let count: usize = 50;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let server_key = key;
    let server_padding = padding.clone();
    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();

        let mut tunnel = VpnTunnel::server(&conn, server_key).await.unwrap();
        tunnel.set_padding(server_padding);
        let (mut tx, mut rx) = tunnel.split();

        for i in 0..count {
            let pkt = rx.recv_packet().await.unwrap();
            let expected = format!("pkt-{i}");
            assert_eq!(pkt, expected.as_bytes(), "mismatch at packet {i}");
            tx.send_packet(pkt.as_slice()).await.unwrap();
        }
        let _ = done_rx.await;
    });

    let conn = connect_client(addr).await;
    let mut tunnel = VpnTunnel::client(&conn, key).await.unwrap();
    tunnel.set_padding(padding);
    let (mut tx, mut rx) = tunnel.split();

    for i in 0..count {
        let msg = format!("pkt-{i}");
        tx.send_packet(msg.as_bytes()).await.unwrap();
        let reply = rx.recv_packet().await.unwrap();
        assert_eq!(reply, msg.as_bytes());
    }

    let _ = done_tx.send(());
    server.await.unwrap();
}

// =========================================================================
// 5. DPI-Aware QUIC Connection Test
// =========================================================================

#[tokio::test]
async fn test_dpi_client_connects_with_chrome_fingerprint() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (ep, addr) = setup_server().await;

    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        // Just verify connection succeeds
        conn.close(0u32.into(), b"ok");
    });

    let dpi = DpiProfile {
        sni: Some("www.example.com".into()),
        fingerprint: FingerprintPreset::Chrome130,
        alpn: vec!["h3".into()],
        ..DpiProfile::default()
    };

    let mut transport = QuicTransport::new(TransportConfig::default());
    transport.bind_client_with_dpi(&dpi).await.unwrap();
    // Connect with custom SNI
    transport.connect(addr, "www.example.com").await.unwrap();

    let conn = transport.connection().unwrap();
    assert!(conn.remote_address().port() > 0);

    server.await.unwrap();
}

#[tokio::test]
async fn test_dpi_client_connects_with_firefox_fingerprint() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (ep, addr) = setup_server().await;

    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let _conn = incoming.await.unwrap();
    });

    let dpi = DpiProfile {
        fingerprint: FingerprintPreset::Firefox120,
        ..DpiProfile::default()
    };

    let mut transport = QuicTransport::new(TransportConfig::default());
    transport.bind_client_with_dpi(&dpi).await.unwrap();
    transport.connect(addr, "localhost").await.unwrap();

    assert!(transport.connection().is_some());
    server.await.unwrap();
}

// =========================================================================
// 6. Shaping Profile Tests
// =========================================================================

#[test]
fn test_shaping_profiles_parse() {
    assert_eq!(ShapingProfile::from_str("none").unwrap(), ShapingProfile::None);
    assert_eq!(ShapingProfile::from_str("browsing").unwrap(), ShapingProfile::Browsing);
    assert_eq!(ShapingProfile::from_str("streaming").unwrap(), ShapingProfile::Streaming);
    assert!(ShapingProfile::from_str("invalid").is_err());
}

#[test]
fn test_fingerprint_presets_parse() {
    assert_eq!(
        FingerprintPreset::from_str("chrome_130").unwrap(),
        FingerprintPreset::Chrome130
    );
    assert_eq!(
        FingerprintPreset::from_str("chrome").unwrap(),
        FingerprintPreset::Chrome130
    );
    assert_eq!(
        FingerprintPreset::from_str("firefox_120").unwrap(),
        FingerprintPreset::Firefox120
    );
    assert_eq!(
        FingerprintPreset::from_str("firefox").unwrap(),
        FingerprintPreset::Firefox120
    );
    assert_eq!(
        FingerprintPreset::from_str("rustls_default").unwrap(),
        FingerprintPreset::RustlsDefault
    );
    assert!(FingerprintPreset::from_str("ie6").is_err());
}

// =========================================================================
// 7. Backward Compatibility
// =========================================================================

#[tokio::test]
async fn test_unpadded_tunnel_still_works() {
    // Verify that the default (no padding) tunnel still works
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = derive_session_key(b"test-psk", b"salt", b"compat-test");

    let (ep, addr) = setup_server().await;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let server_key = key;
    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let tunnel = VpnTunnel::server(&conn, server_key).await.unwrap();
        let (mut tx, mut rx) = tunnel.split();
        let pkt = rx.recv_packet().await.unwrap();
        assert_eq!(pkt, b"no padding");
        tx.send_packet(b"no padding reply").await.unwrap();
        let _ = done_rx.await;
    });

    let conn = connect_client(addr).await;
    let tunnel = VpnTunnel::client(&conn, key).await.unwrap();
    let (mut tx, mut rx) = tunnel.split();

    tx.send_packet(b"no padding").await.unwrap();
    let reply = rx.recv_packet().await.unwrap();
    assert_eq!(reply, b"no padding reply");

    let _ = done_tx.send(());
    server.await.unwrap();
}
