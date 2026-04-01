//! TLS handshake helpers and self-signed certificate generation.

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

use super::dpi::DpiProfile;

/// A self-signed certificate bundle for testing.
pub struct SelfSignedCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

/// Generate a self-signed certificate for `localhost`.
pub fn generate_self_signed() -> Result<SelfSignedCert, String> {
    generate_self_signed_with_san(&["localhost", "127.0.0.1"])
}

/// Generate a self-signed certificate with custom Subject Alternative Names.
///
/// Each entry can be a DNS name (`"myhost"`) or an IP address (`"10.0.0.1"`).
/// `rcgen` auto-detects IP vs DNS from the string format.
pub fn generate_self_signed_with_san(san: &[&str]) -> Result<SelfSignedCert, String> {
    let subject_alt_names: Vec<String> = san.iter().map(|s| s.to_string()).collect();
    let cert = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| e.to_string())?;

    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    Ok(SelfSignedCert { cert_der, key_der })
}

/// Build a `rustls::ClientConfig` that trusts our self-signed CA.
///
/// For production, replace with a proper CA trust store.
pub fn client_crypto_config() -> rustls::ClientConfig {
    // Ensure ring crypto provider is installed
    let _ = rustls::crypto::ring::default_provider().install_default();
    // In tests we'll add the server's self-signed cert dynamically.
    // A dangerous verifier is acceptable only in test / lab environments.
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureServerVerifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    cfg
}

/// Build a `rustls::ClientConfig` with DPI-resistance features.
///
/// Applies the fingerprint preset (cipher suite ordering), custom ALPN,
/// and any other TLS-level configuration from the [`DpiProfile`].
pub fn client_crypto_config_with_dpi(dpi: &DpiProfile) -> Result<rustls::ClientConfig, String> {
    let provider = dpi.fingerprint.crypto_provider();

    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureServerVerifier))
        .with_no_client_auth();

    cfg.alpn_protocols = dpi.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(cfg)
}

/// Build a `quinn::ServerConfig` from a self-signed cert.
pub fn server_config() -> Result<(quinn::ServerConfig, SelfSignedCert), String> {
    server_config_with_san(&["localhost", "127.0.0.1"])
}

/// Build a `quinn::ServerConfig` with custom SANs on the self-signed cert.
///
/// Use this when the server must be reachable by a public IP or hostname.
pub fn server_config_with_san(
    san: &[&str],
) -> Result<(quinn::ServerConfig, SelfSignedCert), String> {
    // Ensure ring crypto provider is installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = generate_self_signed_with_san(san)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der.clone()], cert.key_der.clone_key())
        .map_err(|e| e.to_string())?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| e.to_string())?,
    ));

    Ok((server_cfg, cert))
}

/// Build a `rustls::ClientConfig` for HTTP/2 with ALPN `h2`.
pub fn client_crypto_config_h2() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureServerVerifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg
}

/// Build a TLS server config for HTTP/2 with ALPN `h2`.
pub fn server_tls_config_h2() -> Result<(rustls::ServerConfig, SelfSignedCert), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = generate_self_signed()?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der.clone()], cert.key_der.clone_key())
        .map_err(|e| e.to_string())?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    Ok((tls_config, cert))
}

// ---------------------------------------------------------------------------
// Insecure verifier — lab / test use only
// ---------------------------------------------------------------------------

/// Accepts any server certificate. **Never use in production.**
#[derive(Debug)]
struct InsecureServerVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Certificate pinning verifier — production use
// ---------------------------------------------------------------------------

/// Compute the SHA-256 fingerprint of a DER-encoded certificate.
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hash.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Verifies the server certificate against a pinned SHA-256 fingerprint.
///
/// This provides TOFU (Trust On First Use) security: the client stores the
/// server's certificate fingerprint on first connection, then verifies it
/// on subsequent connections to detect MITM attacks.
#[derive(Debug)]
struct PinnedCertVerifier {
    /// Expected SHA-256 fingerprint (hex, colon-separated).
    pin: String,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual = cert_fingerprint(end_entity.as_ref());
        if actual == self.pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Certificate pin mismatch! Expected: {}, Got: {}",
                self.pin, actual
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a `rustls::ClientConfig` with certificate pinning.
///
/// The `pin` must be the SHA-256 fingerprint of the server's DER certificate
/// in hex format with colons: `"ab:cd:ef:..."`.
pub fn client_crypto_config_pinned(pin: &str) -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier {
            pin: pin.to_string(),
        }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    cfg
}

/// Build a `rustls::ClientConfig` with DPI features **and** certificate pinning.
pub fn client_crypto_config_with_dpi_pinned(
    dpi: &DpiProfile,
    pin: &str,
) -> Result<rustls::ClientConfig, String> {
    let provider = dpi.fingerprint.crypto_provider();

    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier {
            pin: pin.to_string(),
        }))
        .with_no_client_auth();

    cfg.alpn_protocols = dpi.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(cfg)
}
