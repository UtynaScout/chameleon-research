//! Transport layer tests (Phase 2.2).
//!
//! These tests use loopback (127.0.0.1) with self-signed certificates
//! for QUIC and HTTP/2, ensuring they work in lab environments without
//! network access.

use std::net::SocketAddr;

use chameleon_core::transport::{
    QuicTransport, Transport, TransportConfig, TransportMode,
};

// ---------------------------------------------------------------------------
// 1. QUIC loopback: server ↔ client roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_quic_loopback_roundtrip() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Start server
    let (server_ep, _cert) = QuicTransport::bind_server(addr).await.unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let payload = b"chameleon-quic-test-payload";

    // Server task: accept one connection, read one stream
    let server_handle = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let data = QuicTransport::recv(&conn).await.unwrap();
        // Close server side after receiving
        conn.close(0u32.into(), b"done");
        data
    });

    // Client: connect and send
    let mut client = QuicTransport::new(TransportConfig::default());
    client.bind_client().await.unwrap();
    client.connect(server_addr, "localhost").await.unwrap();
    client.send(payload).await.unwrap();

    // Wait for server to receive before closing
    let received = server_handle.await.unwrap();
    client.close();

    assert_eq!(received, payload);
}

// ---------------------------------------------------------------------------
// 2. QUIC multiple streams (multiplexing)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_quic_multiplexed_streams() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_ep, _cert) = QuicTransport::bind_server(addr).await.unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let stream_count: usize = 3;

    let server_handle = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let mut results = Vec::new();
        for _ in 0..3usize {
            let data = QuicTransport::recv(&conn).await.unwrap();
            results.push(data);
        }
        conn.close(0u32.into(), b"done");
        results
    });

    let mut client = QuicTransport::new(TransportConfig::default());
    client.bind_client().await.unwrap();
    client.connect(server_addr, "localhost").await.unwrap();

    for i in 0..stream_count {
        let msg = format!("stream-{i}");
        client.send(msg.as_bytes()).await.unwrap();
    }

    // Wait for server to process all streams before closing
    let results = server_handle.await.unwrap();
    client.close();

    assert_eq!(results.len(), stream_count);
    for (i, data) in results.iter().enumerate() {
        assert_eq!(data, format!("stream-{i}").as_bytes());
    }
}

// ---------------------------------------------------------------------------
// 3. Transport config defaults
// ---------------------------------------------------------------------------

#[test]
fn test_transport_config_defaults() {
    let cfg = TransportConfig::default();
    assert_eq!(cfg.mode, TransportMode::Auto);
    assert_eq!(cfg.mtu, 1200);
    assert_eq!(cfg.max_connections, 8);
    assert_eq!(cfg.idle_timeout_ms, 30_000);
    assert_eq!(cfg.handshake_timeout_ms, 5_000);
}

// ---------------------------------------------------------------------------
// 4. Self-signed certificate generation
// ---------------------------------------------------------------------------

#[test]
fn test_self_signed_cert_generation() {
    use chameleon_core::transport::handshake;
    let cert = handshake::generate_self_signed()
        .expect("self-signed cert generation must succeed");
    // Verify cert_der is non-empty
    assert!(!cert.cert_der.is_empty(), "cert DER must be non-empty");
}

// ---------------------------------------------------------------------------
// 5. End-to-end: weaver → frame → crypto → QUIC transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_end_to_end_weaver_crypto_quic() {
    use chameleon_core::crypto;
    use chameleon_core::frame::ChameleonFrame;
    use chameleon_core::frame::model::FrameType;
    use chameleon_core::weaver::{WeaverEngine, WeaverProfile};

    // 1. Generate session
    let mut engine = WeaverEngine::new(WeaverProfile::default());
    let session = engine.generate_session(2.0);
    let pkt = &session[0];

    // 2. Build frame
    let frame = ChameleonFrame {
        stream_id: 1,
        frame_type: FrameType::Data,
        payload: vec![0xBB; pkt.size_bytes.min(512)],
    };

    // 3. Encrypt
    let key = crypto::derive_session_key(b"lab-psk", b"salt", b"e2e-quic");
    let nonce = [0x01; 12];
    let aad = b"quic-transport-test";
    let encrypted = frame.encrypt_with_aad(&key, &nonce, aad).unwrap();

    // 4. QUIC transport roundtrip
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_ep, _cert) = QuicTransport::bind_server(addr).await.unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let data = QuicTransport::recv(&conn).await.unwrap();
        conn.close(0u32.into(), b"done");
        data
    });

    let mut client = QuicTransport::new(TransportConfig::default());
    client.bind_client().await.unwrap();
    client.connect(server_addr, "localhost").await.unwrap();
    client.send(&encrypted).await.unwrap();

    let received = server_handle.await.unwrap();
    client.close();

    assert_eq!(received, encrypted);

    // 5. Decrypt and verify
    let recovered = ChameleonFrame::decrypt_with_aad(&received, &key, &nonce, aad).unwrap();
    assert_eq!(recovered, frame);
}

// ---------------------------------------------------------------------------
// 6. HTTP/2 echo roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_http2_echo_roundtrip() {
    use chameleon_core::transport::http2::Http2Server;
    use chameleon_core::transport::Http2Transport;

    let server = Http2Server::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let payload = b"http2-test-payload";

    let server_handle = tokio::spawn(async move { server.accept_and_echo().await.unwrap() });

    let client = Http2Transport::new(TransportConfig::default());
    let mut conn = client.connect(server_addr, "localhost").await.unwrap();
    let response = conn.send(payload).await.unwrap();

    let received = server_handle.await.unwrap();

    assert_eq!(received, payload);
    assert_eq!(response, payload); // echoed back
}

// ---------------------------------------------------------------------------
// 7. Unified Transport: encrypt frame → QUIC → decrypt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_transport_unified_send_frame() {
    use chameleon_core::crypto;
    use chameleon_core::frame::model::FrameType;
    use chameleon_core::frame::ChameleonFrame;

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_ep, _cert) = QuicTransport::bind_server(addr).await.unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let key = crypto::derive_session_key(b"psk", b"salt", b"unified");
    let nonce = [0x42; 12];

    let frame = ChameleonFrame {
        stream_id: 7,
        frame_type: FrameType::Data,
        payload: vec![0xAA; 100],
    };

    let server_handle = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let data = QuicTransport::recv(&conn).await.unwrap();
        conn.close(0u32.into(), b"done");
        ChameleonFrame::decrypt_with_aad(&data, &key, &nonce, b"transport-test").unwrap()
    });

    let mut config = TransportConfig::default();
    config.mode = TransportMode::Quic;
    let mut transport = Transport::new(config, key);
    transport.connect(server_addr, "localhost").await.unwrap();
    transport
        .send_frame(&frame, &nonce, b"transport-test")
        .await
        .unwrap();

    let recovered = server_handle.await.unwrap();
    transport.close();

    assert_eq!(recovered, frame);
}
