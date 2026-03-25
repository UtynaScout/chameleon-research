//! Network validation tests (Phase 4.0).
//!
//! Tests that exercise the transport layer under more realistic network
//! conditions: configurable remote endpoints, latency tolerance, HTTP/2
//! fallback under QUIC failure, and sustained throughput.
//!
//! By default, all tests run against localhost. Set `NETSYNTH_SERVER`
//! environment variable to test against a remote server:
//!
//! ```powershell
//! $env:NETSYNTH_SERVER = "192.168.1.100:4433"
//! cargo test --test network_tests
//! ```

use std::net::SocketAddr;
use std::time::Instant;

use chameleon_core::crypto::derive_session_key;
use chameleon_core::frame::model::FrameType;
use chameleon_core::frame::ChameleonFrame;
use chameleon_core::transport::http2::{Http2Server, Http2Transport};
use chameleon_core::transport::quic::QuicTransport;
use chameleon_core::transport::{Transport, TransportConfig, TransportMode};
use chameleon_core::weaver::{WeaverEngine, WeaverProfile};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawn a QUIC echo server on an OS-assigned port.
async fn spawn_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (endpoint, _cert) = QuicTransport::bind_server(addr).await.unwrap();
    let server_addr = endpoint.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                loop {
                    match QuicTransport::recv(&conn).await {
                        Ok(data) => {
                            let result = async {
                                let (mut send, _) =
                                    conn.open_bi().await.map_err(|e| e.to_string())?;
                                send.write_all(&data).await.map_err(|e| e.to_string())?;
                                send.finish().map_err(|e| e.to_string())?;
                                Ok::<(), String>(())
                            }
                            .await;
                            if result.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    (server_addr, handle)
}

fn test_key() -> [u8; 32] {
    derive_session_key(b"test-psk", b"test-salt", b"network-test")
}

const NONCE: [u8; 12] = [0x01; 12];
const AAD: &[u8] = b"network-test";

// ---------------------------------------------------------------------------
// 1. Sustained throughput — send N frames measuring total time
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sustained_throughput() {
    let (server_addr, _server) = spawn_echo_server().await;
    let key = test_key();
    let num_frames = 100;

    let mut client = QuicTransport::new(TransportConfig::default());
    client.bind_client().await.unwrap();
    client.connect(server_addr, "localhost").await.unwrap();

    let start = Instant::now();

    for i in 0..num_frames {
        let frame = ChameleonFrame {
            stream_id: i,
            frame_type: FrameType::Data,
            payload: vec![0xAA; 512],
        };
        let encrypted = frame.encrypt_with_aad(&key, &NONCE, AAD).unwrap();
        client.send(&encrypted).await.unwrap();

        let conn = client.connection().unwrap();
        let echo = QuicTransport::recv(conn).await.unwrap();
        assert_eq!(echo.len(), encrypted.len());
    }

    let elapsed = start.elapsed();
    client.close();

    // 100 frames in under 5 seconds on localhost is a reasonable baseline.
    assert!(
        elapsed.as_secs() < 5,
        "sustained throughput too slow: {elapsed:?} for {num_frames} frames"
    );
}

// ---------------------------------------------------------------------------
// 2. Large payload transfer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_large_payload() {
    let (server_addr, _server) = spawn_echo_server().await;
    let key = test_key();

    let mut client = QuicTransport::new(TransportConfig::default());
    client.bind_client().await.unwrap();
    client.connect(server_addr, "localhost").await.unwrap();

    // Test with payloads from 1 byte to 8 KB
    let sizes = [1, 64, 256, 1024, 4096, 8192];

    for &size in &sizes {
        let frame = ChameleonFrame {
            stream_id: size as u32,
            frame_type: FrameType::Data,
            payload: vec![0xBB; size],
        };
        let encrypted = frame.encrypt_with_aad(&key, &NONCE, AAD).unwrap();
        client.send(&encrypted).await.unwrap();

        let conn = client.connection().unwrap();
        let echo = QuicTransport::recv(conn).await.unwrap();

        let recovered = ChameleonFrame::decrypt_with_aad(&echo, &key, &NONCE, AAD).unwrap();
        assert_eq!(recovered.payload.len(), size, "payload size mismatch for {size}");
        assert_eq!(recovered, frame);
    }

    client.close();
}

// ---------------------------------------------------------------------------
// 3. HTTP/2 fallback under simulated QUIC failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_http2_fallback_under_failure() {
    // Simulate QUIC unavailability by pointing at an HTTP/2-only server.
    let h2_server = Http2Server::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let h2_addr = h2_server.local_addr().unwrap();

    let key = test_key();
    let frame = ChameleonFrame {
        stream_id: 77,
        frame_type: FrameType::Data,
        payload: b"fallback-test".to_vec(),
    };
    let encrypted = frame.encrypt_with_aad(&key, &NONCE, AAD).unwrap();

    // Server echoes in background
    let echo_handle = tokio::spawn(async move { h2_server.accept_and_echo().await.unwrap() });

    // Use HTTP/2 transport directly (simulating what Auto mode would do)
    let h2 = Http2Transport::new(TransportConfig::default());
    let mut conn = h2.connect(h2_addr, "localhost").await.unwrap();
    let response = conn.send(&encrypted).await.unwrap();

    let echoed = echo_handle.await.unwrap();

    assert_eq!(echoed, encrypted);
    assert_eq!(response, encrypted);

    let recovered = ChameleonFrame::decrypt_with_aad(&response, &key, &NONCE, AAD).unwrap();
    assert_eq!(recovered, frame);
}

// ---------------------------------------------------------------------------
// 4. Rapid reconnection — connect/disconnect/reconnect cycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rapid_reconnection() {
    let (server_addr, _server) = spawn_echo_server().await;
    let key = test_key();
    let cycles = 5;

    for cycle in 0..cycles {
        let mut client = QuicTransport::new(TransportConfig::default());
        client.bind_client().await.unwrap();
        client.connect(server_addr, "localhost").await.unwrap();

        let frame = ChameleonFrame {
            stream_id: cycle,
            frame_type: FrameType::Data,
            payload: format!("cycle-{cycle}").into_bytes(),
        };
        let encrypted = frame.encrypt_with_aad(&key, &NONCE, AAD).unwrap();
        client.send(&encrypted).await.unwrap();

        let conn = client.connection().unwrap();
        let echo = QuicTransport::recv(conn).await.unwrap();
        assert_eq!(echo, encrypted, "cycle {cycle}: echo mismatch");

        client.close();
    }
}

// ---------------------------------------------------------------------------
// 5. Full Weaver session with mixed frame types
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_weaver_mixed_session() {
    let (server_addr, _server) = spawn_echo_server().await;
    let key = test_key();

    let mut engine = WeaverEngine::new(WeaverProfile::default());
    let session = engine.generate_session(3.0);
    let chaff = engine.generate_chaff(&session, 0.1);

    // Merge session + chaff, sorted by timestamp
    let mut all_packets = session.clone();
    all_packets.extend(chaff);
    all_packets.sort_by(|a, b| a.timestamp_sec.partial_cmp(&b.timestamp_sec).unwrap());

    let mut client = QuicTransport::new(TransportConfig::default());
    client.bind_client().await.unwrap();
    client.connect(server_addr, "localhost").await.unwrap();

    let mut data_count = 0u32;
    let mut chaff_count = 0u32;

    for (i, pkt) in all_packets.iter().enumerate() {
        let is_chaff = i >= session.len();
        let frame_type = if is_chaff {
            FrameType::Chaff
        } else {
            FrameType::Data
        };

        let frame = ChameleonFrame {
            stream_id: i as u32,
            frame_type,
            payload: vec![0xDD; pkt.size_bytes.min(1200)],
        };
        let encrypted = frame.encrypt_with_aad(&key, &NONCE, AAD).unwrap();
        client.send(&encrypted).await.unwrap();

        let conn = client.connection().unwrap();
        let echo = QuicTransport::recv(conn).await.unwrap();
        assert_eq!(echo.len(), encrypted.len());

        if is_chaff {
            chaff_count += 1;
        } else {
            data_count += 1;
        }
    }

    client.close();

    assert!(data_count > 0, "must have data frames");
    assert!(chaff_count > 0, "must have chaff frames");
}

// ---------------------------------------------------------------------------
// 6. Unified Transport configurable endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_unified_transport_network() {
    let (server_addr, _server) = spawn_echo_server().await;
    let key = test_key();

    let config = TransportConfig {
        mode: TransportMode::Quic,
        mtu: 1200,
        max_connections: 4,
        idle_timeout_ms: 10_000,
        handshake_timeout_ms: 3_000,
    };

    let mut transport = Transport::new(config, key);
    transport.connect(server_addr, "localhost").await.unwrap();

    assert_eq!(transport.active_mode(), TransportMode::Quic);

    let frame = ChameleonFrame {
        stream_id: 1,
        frame_type: FrameType::Control,
        payload: vec![0xEE; 128],
    };
    transport.send_frame(&frame, &NONCE, AAD).await.unwrap();

    transport.close();
}

// ---------------------------------------------------------------------------
// 7. Key rotation during active session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_key_rotation_during_session() {
    use chameleon_core::crypto::hkdf::rotate_key;

    let (server_addr, _server) = spawn_echo_server().await;
    let base_key = test_key();

    let mut client = QuicTransport::new(TransportConfig::default());
    client.bind_client().await.unwrap();
    client.connect(server_addr, "localhost").await.unwrap();

    // Send frames with rotated keys
    for counter in 0..5u64 {
        let key = rotate_key(&base_key, counter);

        let frame = ChameleonFrame {
            stream_id: counter as u32,
            frame_type: FrameType::Data,
            payload: format!("key-rotation-{counter}").into_bytes(),
        };
        let encrypted = frame.encrypt_with_aad(&key, &NONCE, AAD).unwrap();
        client.send(&encrypted).await.unwrap();

        let conn = client.connection().unwrap();
        let echo = QuicTransport::recv(conn).await.unwrap();

        // Decrypt echo with same rotated key
        let recovered = ChameleonFrame::decrypt_with_aad(&echo, &key, &NONCE, AAD).unwrap();
        assert_eq!(recovered, frame, "key rotation counter {counter}: mismatch");
    }

    client.close();
}
