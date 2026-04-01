//! Phase 8 — Stability & Security tests.
//!
//! Tests for DNS interception, keep-alive, reconnect, and cert pinning.

use chameleon_core::transport::handshake;
use chameleon_core::transport::reconnect::ReconnectConfig;
use chameleon_core::tun::dns::DnsInterceptor;
use chameleon_core::tun::keepalive;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Certificate pinning tests
// ---------------------------------------------------------------------------

#[test]
fn test_cert_fingerprint_deterministic() {
    let cert = handshake::generate_self_signed().unwrap();
    let fp1 = handshake::cert_fingerprint(cert.cert_der.as_ref());
    let fp2 = handshake::cert_fingerprint(cert.cert_der.as_ref());
    assert_eq!(fp1, fp2);
    // SHA-256 has 32 bytes = 64 hex chars + 31 colons = 95 chars
    assert_eq!(fp1.len(), 95);
    assert!(fp1.contains(':'));
}

#[test]
fn test_cert_fingerprint_different_certs() {
    let cert1 = handshake::generate_self_signed().unwrap();
    let cert2 = handshake::generate_self_signed().unwrap();
    let fp1 = handshake::cert_fingerprint(cert1.cert_der.as_ref());
    let fp2 = handshake::cert_fingerprint(cert2.cert_der.as_ref());
    assert_ne!(fp1, fp2, "Different certs should have different fingerprints");
}

#[test]
fn test_pinned_client_config_creates_successfully() {
    let cert = handshake::generate_self_signed().unwrap();
    let pin = handshake::cert_fingerprint(cert.cert_der.as_ref());
    // Should not panic
    let _config = handshake::client_crypto_config_pinned(&pin);
}

#[test]
fn test_pinned_client_config_with_dpi() {
    use chameleon_core::transport::dpi::DpiProfile;
    let cert = handshake::generate_self_signed().unwrap();
    let pin = handshake::cert_fingerprint(cert.cert_der.as_ref());
    let dpi = DpiProfile::default();
    let config = handshake::client_crypto_config_with_dpi_pinned(&dpi, &pin);
    assert!(config.is_ok());
}

#[test]
fn test_self_signed_with_san_includes_ip() {
    let cert = handshake::generate_self_signed_with_san(&["77.110.97.128", "localhost"]).unwrap();
    let fp = handshake::cert_fingerprint(cert.cert_der.as_ref());
    assert_eq!(fp.len(), 95);
}

// ---------------------------------------------------------------------------
// Keep-alive tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_keepalive_sends_pings() {
    let interval = Duration::from_millis(50);
    let (handle, mut rx) = keepalive::spawn_keepalive(interval);

    // Should receive at least one ping within 200ms
    let result = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
    assert!(result.is_ok(), "Should have received a keepalive ping");
    assert!(result.unwrap().is_some(), "Channel should not be closed");

    handle.stop();
}

#[tokio::test]
async fn test_keepalive_stop() {
    let interval = Duration::from_millis(50);
    let (handle, mut rx) = keepalive::spawn_keepalive(interval);

    // Wait for first ping
    let _ = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;

    // Stop keepalive
    handle.stop();

    // Allow the task to notice the stop
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Channel should eventually close or stop producing
    // Drain any buffered pings
    while rx.try_recv().is_ok() {}
}

#[tokio::test]
async fn test_keepalive_multiple_pings() {
    let interval = Duration::from_millis(30);
    let (handle, mut rx) = keepalive::spawn_keepalive(interval);

    let mut count = 0;
    for _ in 0..3 {
        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        if result.is_ok() {
            count += 1;
        }
    }
    assert!(count >= 2, "Should have received at least 2 pings, got {count}");

    handle.stop();
}

// ---------------------------------------------------------------------------
// Reconnect config tests
// ---------------------------------------------------------------------------

#[test]
fn test_reconnect_config_defaults() {
    let cfg = ReconnectConfig::default();
    assert_eq!(cfg.max_retries, 0); // unlimited
    assert_eq!(cfg.initial_delay, Duration::from_secs(1));
    assert_eq!(cfg.max_delay, Duration::from_secs(30));
    assert!((cfg.backoff_factor - 2.0).abs() < f64::EPSILON);
}

#[tokio::test]
async fn test_reconnect_fails_on_invalid_server() {
    use chameleon_core::transport::dpi::DpiProfile;

    let cfg = ReconnectConfig {
        max_retries: 2,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(50),
        backoff_factor: 2.0,
        connect_timeout: Duration::from_millis(500),
    };

    // Connect to an invalid address — should fail after max_retries
    let result = chameleon_core::transport::reconnect::connect_with_retry(
        "127.0.0.1:1".parse().unwrap(), // nothing listens on port 1
        "localhost",
        &DpiProfile::default(),
        &cfg,
    )
    .await;

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("Failed after 2 attempts"), "Got: {err}");
}

// ---------------------------------------------------------------------------
// DNS interceptor tests (unit-level, no root required)
// ---------------------------------------------------------------------------

#[test]
fn test_dns_interceptor_new() {
    let interceptor = DnsInterceptor::new("tun0", "10.8.0.2");
    // Just verify it doesn't panic
    drop(interceptor);
}

#[test]
fn test_default_dns_servers() {
    use chameleon_core::tun::dns::DEFAULT_DNS_SERVERS;
    assert!(!DEFAULT_DNS_SERVERS.is_empty());
    assert!(DEFAULT_DNS_SERVERS.contains(&"8.8.8.8"));
    assert!(DEFAULT_DNS_SERVERS.contains(&"1.1.1.1"));
}
