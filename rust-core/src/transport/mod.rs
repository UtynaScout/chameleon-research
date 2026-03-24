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

pub use handshake::SelfSignedCert;
pub use http2::Http2Transport;
pub use quic::QuicTransport;
