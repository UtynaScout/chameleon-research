//! HTTP/2 transport fallback using the `h2` crate.

use std::net::SocketAddr;
use std::sync::Arc;

use h2::client;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
    ///
    /// Uses `config.handshake_timeout_ms` as the TCP connect timeout.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Http2ClientConnection, TransportError> {
        let tcp = tokio::time::timeout(
            std::time::Duration::from_millis(self.config.handshake_timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let crypto = handshake::client_crypto_config_h2();
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

/// Minimal HTTP/2 echo server for testing.
///
/// Binds a TCP listener, accepts one connection with TLS + h2 handshake,
/// reads the first request body, echoes it as the response, and returns
/// the received bytes.
pub struct Http2Server {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

impl Http2Server {
    /// Bind to `addr` with a self-signed TLS certificate.
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let (tls_config, _cert) = handshake::server_tls_config_h2()
            .map_err(TransportError::HandshakeFailed)?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok(Self { listener, tls_acceptor })
    }

    /// Returns the local address this server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.listener
            .local_addr()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }

    /// Accept one connection, read the first request body, echo it back,
    /// and return the received bytes.
    pub async fn accept_and_echo(&self) -> Result<Vec<u8>, TransportError> {
        let (tcp, _) = self
            .listener
            .accept()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let tls = self
            .tls_acceptor
            .accept(tcp)
            .await
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

        let mut connection = h2::server::handshake(tls)
            .await
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or_else(|| TransportError::ReceiveFailed("no request received".into()))?
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;

        // Drive the connection in the background so response frames get flushed.
        tokio::spawn(async move {
            while let Some(Ok(_)) = connection.accept().await {}
        });

        let mut body = request.into_body();
        let mut received = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
            received.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }

        let response = http::Response::builder().status(200).body(()).unwrap();
        let mut send = respond
            .send_response(response, false)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        send.send_data(bytes::Bytes::copy_from_slice(&received), true)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        Ok(received)
    }
}
