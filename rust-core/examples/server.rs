//! Chameleon QUIC echo server example.
//!
//! Accepts encrypted frames over QUIC, decrypts them, logs the payload,
//! and echoes the ciphertext back to the client.
//!
//! ```powershell
//! cargo run --example server -- --port 4433
//! ```

use std::net::SocketAddr;

use chameleon_core::crypto::derive_session_key;
use chameleon_core::frame::ChameleonFrame;
use chameleon_core::transport::quic::QuicTransport;
use clap::Parser;
use tracing::{info, warn};

/// Chameleon QUIC echo server.
#[derive(Parser)]
#[command(name = "chameleon-server")]
struct Args {
    /// Port to listen on.
    #[arg(short, long, default_value_t = 4433)]
    port: u16,

    /// Pre-shared key material for HKDF.
    #[arg(long, default_value = "lab-psk")]
    psk: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let key = derive_session_key(args.psk.as_bytes(), b"chameleon-salt", b"server-session");

    info!("Starting Chameleon server on {addr}");

    let (endpoint, _cert) = QuicTransport::bind_server(addr).await?;
    let local_addr = endpoint.local_addr()?;
    info!("Listening on {local_addr}");

    // Graceful shutdown on Ctrl+C
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    info!("Endpoint closed, shutting down");
                    break;
                };

                let key = key;
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            let remote = conn.remote_address();
                            info!(%remote, "Accepted connection");
                            handle_connection(conn, &key).await;
                        }
                        Err(e) => warn!("Failed to accept connection: {e}"),
                    }
                });
            }
            _ = &mut shutdown => {
                info!("Ctrl+C received, shutting down");
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connection, key: &[u8; 32]) {
    let remote = conn.remote_address();
    let nonce = [0x01; 12];
    let aad = b"chameleon-e2e";

    loop {
        match QuicTransport::recv(&conn).await {
            Ok(data) => {
                info!(%remote, bytes = data.len(), "Received data");

                // Try to decrypt as a ChameleonFrame
                match ChameleonFrame::decrypt_with_aad(&data, key, &nonce, aad) {
                    Ok(frame) => {
                        info!(
                            %remote,
                            stream_id = frame.stream_id,
                            frame_type = ?frame.frame_type,
                            payload_len = frame.payload.len(),
                            "Decrypted frame"
                        );
                    }
                    Err(e) => {
                        warn!(%remote, "Frame decrypt failed (echoing raw): {e}");
                    }
                }

                // Echo the ciphertext back
                if let Err(e) = echo_back(&conn, &data).await {
                    warn!(%remote, "Echo failed: {e}");
                    break;
                }
            }
            Err(e) => {
                info!(%remote, "Connection ended: {e}");
                break;
            }
        }
    }
}

async fn echo_back(
    conn: &quinn::Connection,
    data: &[u8],
) -> Result<(), chameleon_core::transport::TransportError> {
    let (mut send, _recv) = conn
        .open_bi()
        .await
        .map_err(|e| chameleon_core::transport::TransportError::SendFailed(e.to_string()))?;

    send.write_all(data)
        .await
        .map_err(|e| chameleon_core::transport::TransportError::SendFailed(e.to_string()))?;

    send.finish()
        .map_err(|_| chameleon_core::transport::TransportError::SendFailed("finish failed".into()))?;

    Ok(())
}
