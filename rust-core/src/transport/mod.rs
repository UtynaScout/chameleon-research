//! Transport layer for the Chameleon protocol.
//!
//! Provides QUIC (primary) and HTTP/2 (fallback) transports.

pub mod handshake;
pub mod http2;
pub mod quic;

use thiserror::Error;

/// Transport mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// UDP-based QUIC transport (preferred).
    Quic,
    /// TCP-based HTTP/2 fallback.
    Http2,
    /// Try QUIC first, fall back to HTTP/2 on failure.
    Auto,
}

/// Transport configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub mode: TransportMode,
    pub mtu: usize,
    pub max_connections: usize,
    pub idle_timeout_ms: u64,
    pub handshake_timeout_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: TransportMode::Auto,
            mtu: 1200, // QUIC-recommended initial MTU
            max_connections: 8,
            idle_timeout_ms: 30_000,
            handshake_timeout_ms: 5_000,
        }
    }
}

/// Errors from transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("receive failed: {0}")]
    ReceiveFailed(String),
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("timeout")]
    Timeout,
    #[error("pool exhausted (max {max} connections)")]
    PoolExhausted { max: usize },
}

use std::net::SocketAddr;

use crate::frame::ChameleonFrame;

pub use handshake::SelfSignedCert;
pub use http2::{Http2Server, Http2Transport};
pub use quic::QuicTransport;

/// Unified transport that integrates frame encryption with the underlying
/// QUIC (or HTTP/2) connection.
pub struct Transport {
    mode: TransportMode,
    config: TransportConfig,
    crypto_key: [u8; 32],
    quic: Option<QuicTransport>,
}

impl Transport {
    /// Create a new transport with the given configuration and encryption key.
    pub fn new(config: TransportConfig, crypto_key: [u8; 32]) -> Self {
        let mode = config.mode;
        Self {
            mode,
            config,
            crypto_key,
            quic: None,
        }
    }

    /// Connect to a remote peer using the configured transport mode.
    ///
    /// In `Auto` mode, QUIC is tried first.
    pub async fn connect(
        &mut self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<(), TransportError> {
        match self.mode {
            TransportMode::Quic | TransportMode::Auto => {
                let mut quic = QuicTransport::new(self.config.clone());
                quic.bind_client().await?;
                quic.connect(addr, server_name).await?;
                self.quic = Some(quic);
                Ok(())
            }
            TransportMode::Http2 => {
                // HTTP/2 connections are per-request via Http2Transport
                Ok(())
            }
        }
    }

    /// Encrypt a [`ChameleonFrame`] and send it over the transport.
    pub async fn send_frame(
        &self,
        frame: &ChameleonFrame,
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<(), TransportError> {
        let encrypted = frame
            .encrypt_with_aad(&self.crypto_key, nonce, aad)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        self.send_raw(&encrypted).await
    }

    /// Send raw (pre-encrypted) bytes over the transport.
    pub async fn send_raw(&self, data: &[u8]) -> Result<(), TransportError> {
        match &self.quic {
            Some(q) => q.send(data).await,
            None => Err(TransportError::ConnectionFailed("not connected".into())),
        }
    }

    /// Returns the active transport mode.
    pub fn active_mode(&self) -> TransportMode {
        self.mode
    }

    /// Returns the crypto key.
    pub fn crypto_key(&self) -> &[u8; 32] {
        &self.crypto_key
    }

    /// Close the underlying connection.
    pub fn close(&mut self) {
        if let Some(q) = &mut self.quic {
            q.close();
        }
    }
}
