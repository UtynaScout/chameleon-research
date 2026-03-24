//! Cryptographic primitives for the Chameleon protocol.
//!
//! * [`hkdf`] — HKDF key derivation (RFC 5869)
//! * [`cipher`] — ChaCha20-Poly1305 AEAD (RFC 8439)

pub mod cipher;
pub mod hkdf;

use thiserror::Error;

pub use cipher::{decrypt, encrypt};
pub use hkdf::{derive_session_key, rotate_key};

/// Errors returned by cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed (authentication tag mismatch)")]
    DecryptionFailed,
}
