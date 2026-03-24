//! HTTP/2 transport fallback using the `h2` crate.

use std::net::SocketAddr;
use std::sync::Arc;

use h2::client;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::{TransportConfig, TransportError};
use crate::transport::handshake;

/// HTTP/2 transport over TLS 1.3 (TCP fallback for environments blocking UDP).
pub struct Http2Transport {
    config: TransportConfig,
}

impl Http2Transport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }

    /// Connect to a server, perform TLS handshake, and establish HTTP/2 session.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Http2ClientConnection, TransportError> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let crypto = handshake::client_crypto_config();
        let connector = TlsConnector::from(Arc::new(crypto));
        let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

        let tls = connector
            .connect(domain, tcp)
            .await
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

        let (send_request, connection) = client::handshake(tls)
            .await
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

        // Drive the connection in the background
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("HTTP/2 connection error: {e}");
            }
        });

        Ok(Http2ClientConnection { send_request })
    }
}

/// An established HTTP/2 client connection.
pub struct Http2ClientConnection {
    send_request: client::SendRequest<bytes::Bytes>,
}

impl Http2ClientConnection {
    /// Send binary payload as an HTTP/2 POST request body.
    pub async fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        let request = http::Request::builder()
            .method("POST")
            .uri("/chameleon")
            .body(())
            .unwrap();

        let (response_future, mut send_stream) = self
            .send_request
            .send_request(request, false)
            .map_err(|e: h2::Error| TransportError::SendFailed(e.to_string()))?;

        send_stream
            .send_data(bytes::Bytes::copy_from_slice(data), true)
            .map_err(|e: h2::Error| TransportError::SendFailed(e.to_string()))?;

        let response: http::Response<h2::RecvStream> = response_future
            .await
            .map_err(|e: h2::Error| TransportError::ReceiveFailed(e.to_string()))?;

        let mut body = response.into_body();
        let mut result = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk: bytes::Bytes =
                chunk.map_err(|e: h2::Error| TransportError::ReceiveFailed(e.to_string()))?;
            result.extend_from_slice(&chunk);
            body.flow_control()
                .release_capacity(chunk.len())
                .map_err(|e: h2::Error| TransportError::ReceiveFailed(e.to_string()))?;
        }

        Ok(result)
    }
}
