//! VPN tunnel integration tests.
//!
//! These tests exercise [`VpnTunnel`] over a real QUIC connection without
//! needing a TUN device or root privileges, so they run on any platform.

use std::net::SocketAddr;

use chameleon_core::crypto::derive_session_key;
use chameleon_core::transport::quic::QuicTransport;
use chameleon_core::transport::TransportConfig;
use chameleon_core::tun::VpnTunnel;

/// Helper: set up a QUIC server endpoint on localhost with an ephemeral port.
async fn setup_server() -> (quinn::Endpoint, SocketAddr) {
    let (ep, _cert) = QuicTransport::bind_server("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind_server");
    let addr = ep.local_addr().unwrap();
    (ep, addr)
}

/// Helper: connect a QUIC client to the given address.
async fn connect_client(addr: SocketAddr) -> quinn::Connection {
    let mut t = QuicTransport::new(TransportConfig::default());
    t.bind_client().await.unwrap();
    t.connect(addr, "localhost").await.unwrap();
    t.connection().unwrap().clone()
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn vpn_tunnel_roundtrip() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = derive_session_key(b"test-psk", b"salt", b"vpn-test");

    let (ep, addr) = setup_server().await;

    // Keep server alive until client is done
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let server_key = key;
    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();

        let tunnel = VpnTunnel::server(&conn, server_key).await.unwrap();
        let (mut tx, mut rx) = tunnel.split();

        let pkt = rx.recv_packet().await.unwrap();
        assert_eq!(pkt, b"hello from client");

        tx.send_packet(b"hello from server").await.unwrap();

        // Hold connection open until client signals
        let _ = done_rx.await;
    });

    let conn = connect_client(addr).await;
    let tunnel = VpnTunnel::client(&conn, key).await.unwrap();
    let (mut tx, mut rx) = tunnel.split();

    tx.send_packet(b"hello from client").await.unwrap();
    let reply = rx.recv_packet().await.unwrap();
    assert_eq!(reply, b"hello from server");

    let _ = done_tx.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn vpn_tunnel_many_packets() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = derive_session_key(b"test-psk", b"salt", b"vpn-many");

    let (ep, addr) = setup_server().await;
    let count: usize = 100;

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let server_key = key;
    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();

        let tunnel = VpnTunnel::server(&conn, server_key).await.unwrap();
        let (mut tx, mut rx) = tunnel.split();

        for i in 0..count {
            let pkt = rx.recv_packet().await.unwrap();
            let expected = format!("packet-{i}");
            assert_eq!(pkt, expected.as_bytes(), "mismatch at packet {i}");
            tx.send_packet(pkt.as_slice()).await.unwrap();
        }

        let _ = done_rx.await;
    });

    let conn = connect_client(addr).await;
    let tunnel = VpnTunnel::client(&conn, key).await.unwrap();
    let (mut tx, mut rx) = tunnel.split();

    for i in 0..count {
        let payload = format!("packet-{i}");
        tx.send_packet(payload.as_bytes()).await.unwrap();
        let echo = rx.recv_packet().await.unwrap();
        assert_eq!(echo, payload.as_bytes());
    }

    let _ = done_tx.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn vpn_tunnel_large_packet() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = derive_session_key(b"test-psk", b"salt", b"vpn-large");

    let (ep, addr) = setup_server().await;

    // Simulate a 1400-byte IP packet (typical VPN MTU)
    let big_pkt: Vec<u8> = (0..1400).map(|i| (i % 256) as u8).collect();

    let server_key = key;
    let expect = big_pkt.clone();
    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();

        let tunnel = VpnTunnel::server(&conn, server_key).await.unwrap();
        let (_tx, mut rx) = tunnel.split();

        let pkt = rx.recv_packet().await.unwrap();
        assert_eq!(pkt.len(), 1400);
        assert_eq!(pkt, expect);
    });

    let conn = connect_client(addr).await;
    let tunnel = VpnTunnel::client(&conn, key).await.unwrap();
    let (mut tx, _rx) = tunnel.split();

    tx.send_packet(&big_pkt).await.unwrap();
    server.await.unwrap();
}
