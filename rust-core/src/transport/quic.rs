//! QUIC transport layer using the `quinn` crate.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{ClientConfig, Endpoint};

use super::{TransportConfig, TransportError};
use crate::transport::handshake;

/// QUIC transport backed by a `quinn::Endpoint`.
pub struct QuicTransport {
    config: TransportConfig,
    endpoint: Option<Endpoint>,
    connection: Option<quinn::Connection>,
}

impl QuicTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            endpoint: None,
            connection: None,
        }
    }

    /// Bind a client endpoint on an OS-assigned port.
    ///
    /// Applies `config.mtu` as the QUIC initial MTU.
    pub async fn bind_client(&mut self) -> Result<(), TransportError> {
        let crypto = handshake::client_crypto_config();
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

        let mut transport_cfg = quinn::TransportConfig::default();
        transport_cfg.initial_mtu(self.config.mtu as u16);

        let mut client_cfg = ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(Arc::new(transport_cfg));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        endpoint.set_default_client_config(client_cfg);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    /// Create a server endpoint that listens on `addr`.
    pub async fn bind_server(
        addr: SocketAddr,
    ) -> Result<(Endpoint, super::handshake::SelfSignedCert), TransportError> {
        let (server_cfg, cert) = handshake::server_config()
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;
        let endpoint = Endpoint::server(server_cfg, addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok((endpoint, cert))
    }

    /// Create a server endpoint with custom SANs on the self-signed cert.
    ///
    /// Use this when clients connect by IP or a specific hostname.
    pub async fn bind_server_with_san(
        addr: SocketAddr,
        san: &[&str],
    ) -> Result<(Endpoint, super::handshake::SelfSignedCert), TransportError> {
        let (server_cfg, cert) = handshake::server_config_with_san(san)
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;
        let endpoint = Endpoint::server(server_cfg, addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok((endpoint, cert))
    }

    /// Connect to a QUIC server.
    pub async fn connect(&mut self, addr: SocketAddr, server_name: &str) -> Result<(), TransportError> {
        let ep = self
            .endpoint
            .as_ref()
            .ok_or_else(|| TransportError::ConnectionFailed("endpoint not bound".into()))?;

        let conn = ep
            .connect(addr, server_name)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        self.connection = Some(conn);
        Ok(())
    }

    /// Open a new bidirectional stream and send `data`.
    pub async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| TransportError::SendFailed("not connected".into()))?;

        let (mut send, _recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        send.write_all(data)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        send.finish()
            .map_err(|_| TransportError::SendFailed("finish failed".into()))?;

        Ok(())
    }

    /// Accept an incoming bidirectional stream and read all data.
    pub async fn recv(conn: &quinn::Connection) -> Result<Vec<u8>, TransportError> {
        let (_send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;

        let data = recv
            .read_to_end(64 * 1024) // 64 KiB max
            .await
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;

        Ok(data)
    }

    /// Close the connection gracefully.
    pub fn close(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.close(0u32.into(), b"done");
        }
    }

    /// Returns a reference to the underlying QUIC connection, if established.
    pub fn connection(&self) -> Option<&quinn::Connection> {
        self.connection.as_ref()
    }

    /// Returns the configured MTU.
    pub fn mtu(&self) -> usize {
        self.config.mtu
    }
}
