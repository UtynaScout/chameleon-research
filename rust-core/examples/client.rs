//! Chameleon QUIC client example.
//!
//! Generates synthetic traffic via the Weaver engine, encrypts frames,
//! sends them to the server, and collects round-trip statistics.
//!
//! ```powershell
//! cargo run --example client -- --server 127.0.0.1:4433 --duration 5
//! ```

use std::net::SocketAddr;

use chameleon_core::crypto::derive_session_key;
use chameleon_core::frame::model::FrameType;
use chameleon_core::frame::ChameleonFrame;
use chameleon_core::transport::quic::QuicTransport;
use chameleon_core::transport::TransportConfig;
use chameleon_core::weaver::{WeaverEngine, WeaverProfile};
use clap::Parser;
use tracing::{error, info};

/// Chameleon QUIC traffic generator client.
#[derive(Parser)]
#[command(name = "chameleon-client")]
struct Args {
    /// Server address (host:port).
    #[arg(short, long, default_value = "127.0.0.1:4433")]
    server: String,

    /// Duration of the generated session in seconds.
    #[arg(short, long, default_value_t = 5.0)]
    duration: f64,

    /// Pre-shared key material for HKDF.
    #[arg(long, default_value = "lab-psk")]
    psk: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let server_addr: SocketAddr = args.server.parse()?;
    let key = derive_session_key(args.psk.as_bytes(), b"chameleon-salt", b"server-session");
    let nonce = [0x01; 12];
    let aad = b"chameleon-e2e";

    info!("Connecting to {server_addr}");

    let mut client = QuicTransport::new(TransportConfig::default());
    client.bind_client().await?;
    client.connect(server_addr, "localhost").await?;

    info!("Connected, generating {:.1}s session", args.duration);

    // Generate traffic via Weaver
    let mut engine = WeaverEngine::new(WeaverProfile::default());
    let session = engine.generate_session(args.duration);

    let mut sent = 0usize;
    let mut bytes_sent = 0usize;
    let mut echoed = 0usize;

    for pkt in &session {
        let frame = ChameleonFrame {
            stream_id: sent as u32,
            frame_type: FrameType::Data,
            payload: vec![0xAA; pkt.size_bytes.min(1200)],
        };

        let encrypted = frame.encrypt_with_aad(&key, &nonce, aad)?;
        client.send(&encrypted).await?;
        sent += 1;
        bytes_sent += encrypted.len();

        // Read echo from server (server opens a new bi-stream to echo)
        if let Some(conn) = client.connection() {
            match QuicTransport::recv(conn).await {
                Ok(echo) => {
                    if echo == encrypted {
                        echoed += 1;
                    }
                }
                Err(e) => {
                    error!("Echo recv failed: {e}");
                }
            }
        }

        // Respect inter-arrival time
        tokio::time::sleep(std::time::Duration::from_millis(pkt.iat_ms as u64)).await;
    }

    client.close();

    info!("Session complete");
    println!();
    println!("=== Chameleon Client Stats ===");
    println!("  Packets generated : {}", session.len());
    println!("  Packets sent      : {sent}");
    println!("  Bytes sent        : {bytes_sent}");
    println!("  Echoes received   : {echoed}");
    println!("  Echo match rate   : {:.1}%", echoed as f64 / sent.max(1) as f64 * 100.0);
    println!();

    Ok(())
}
