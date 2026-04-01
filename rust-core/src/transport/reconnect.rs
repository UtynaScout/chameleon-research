//! Automatic reconnection with exponential backoff for VPN tunnel.
//!
//! Wraps the QUIC connection establishment in a retry loop that handles
//! transient network failures (WiFi drops, mobile network switches, etc.).

use std::net::SocketAddr;
use std::time::Duration;

use tracing::{info, warn};

use crate::transport::dpi::DpiProfile;
use crate::transport::quic::QuicTransport;
use crate::transport::TransportConfig;

/// Configuration for the reconnect strategy.
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Maximum number of reconnection attempts (0 = unlimited).
    pub max_retries: u32,
    /// Initial delay before the first retry.
    pub initial_delay: Duration,
    /// Maximum delay between retries (caps exponential growth).
    pub max_delay: Duration,
    /// Multiplier for exponential backoff.
    pub backoff_factor: f64,
    /// Timeout for each individual connection attempt.
    pub connect_timeout: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_retries: 0, // unlimited
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_factor: 2.0,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Attempt to establish a QUIC connection with exponential backoff.
///
/// Returns the connected `QuicTransport` or an error if all retries
/// are exhausted.
pub async fn connect_with_retry(
    server_addr: SocketAddr,
    connect_name: &str,
    dpi: &DpiProfile,
    config: &ReconnectConfig,
) -> Result<QuicTransport, String> {
    let mut attempt = 0u32;
    let mut delay = config.initial_delay;

    loop {
        attempt += 1;
        info!(attempt, "Connecting to {server_addr}...");

        match tokio::time::timeout(
            config.connect_timeout,
            try_connect(server_addr, connect_name, dpi),
        )
        .await
        {
            Ok(Ok(transport)) => {
                if attempt > 1 {
                    info!(attempt, "Reconnected successfully");
                }
                return Ok(transport);
            }
            Ok(Err(e)) => {
                if config.max_retries > 0 && attempt >= config.max_retries {
                    return Err(format!(
                        "Failed after {attempt} attempts: {e}"
                    ));
                }

                warn!(
                    attempt,
                    delay_ms = delay.as_millis(),
                    "Connection failed: {e} — retrying"
                );
            }
            Err(_) => {
                if config.max_retries > 0 && attempt >= config.max_retries {
                    return Err(format!(
                        "Failed after {attempt} attempts: connection timeout"
                    ));
                }

                warn!(
                    attempt,
                    delay_ms = delay.as_millis(),
                    "Connection timed out — retrying"
                );
            }
        }

        tokio::time::sleep(delay).await;

        // Exponential backoff with cap
        delay = Duration::from_secs_f64(
            (delay.as_secs_f64() * config.backoff_factor).min(config.max_delay.as_secs_f64()),
        );
    }
}

async fn try_connect(
    server_addr: SocketAddr,
    connect_name: &str,
    dpi: &DpiProfile,
) -> Result<QuicTransport, String> {
    let mut transport = QuicTransport::new(TransportConfig::default());

    if dpi.fingerprint != crate::transport::dpi::FingerprintPreset::RustlsDefault
        || dpi.alpn != vec!["h3".to_string()]
        || dpi.sni.is_some()
    {
        transport
            .bind_client_with_dpi(dpi)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        transport.bind_client().await.map_err(|e| e.to_string())?;
    }

    transport
        .connect(server_addr, connect_name)
        .await
        .map_err(|e| e.to_string())?;

    Ok(transport)
}
