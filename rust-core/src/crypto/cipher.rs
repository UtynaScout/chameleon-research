//! ChaCha20-Poly1305 AEAD cipher following RFC 8439.
//!
//! Provides encrypt / decrypt helpers that accept associated data (AAD)
//! for authenticated encryption.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use super::CryptoError;

/// Encrypt `plaintext` with ChaCha20-Poly1305 AEAD.
///
/// * `key`   – 256-bit symmetric key.
/// * `nonce` – 96-bit unique nonce (**must never be reused** with the same key).
/// * `aad`   – additional authenticated data (integrity-protected but not encrypted).
///
/// Returns ciphertext || 128-bit Poly1305 tag.
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt `ciphertext` produced by [`encrypt`].
///
/// Returns the original plaintext or [`CryptoError::DecryptionFailed`]
/// if the tag verification fails (wrong key, corrupted data, or tampered AAD).
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}
