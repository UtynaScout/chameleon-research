//! HKDF key derivation following RFC 5869.
//!
//! Uses HMAC-SHA-256 as the underlying PRF. All operations are
//! performed through the `hkdf` crate which guarantees constant-time
//! HMAC comparisons internally.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 256-bit session key from a pre-shared key using HKDF-Extract + HKDF-Expand.
///
/// * `master_psk` – pre-shared key material (IKM in RFC 5869 terms).
/// * `salt`       – optional (but recommended) random value.
/// * `info`       – context/application-specific info string.
pub fn derive_session_key(master_psk: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_psk);
    let mut okm = [0u8; 32];
    // expand cannot fail when OKM length <= 255 * HashLen (= 8160 for SHA-256)
    hk.expand(info, &mut okm)
        .expect("32 bytes is within HKDF-SHA256 output limit");
    okm
}

/// Rotate an existing 256-bit key by feeding it back through HKDF
/// together with a monotonic counter, producing a fresh 256-bit key.
///
/// The counter is encoded as little-endian bytes in the `info` field
/// so that each counter value yields a unique derived key.
pub fn rotate_key(current_key: &[u8; 32], counter: u64) -> [u8; 32] {
    let salt = b"chameleon-key-rotation-v1";
    let info = counter.to_le_bytes();
    derive_session_key(current_key, salt, &info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let key1 = derive_session_key(b"secret", b"salt", b"info");
        let key2 = derive_session_key(b"secret", b"salt", b"info");
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_info_yields_different_key() {
        let k1 = derive_session_key(b"psk", b"salt", b"ctx-a");
        let k2 = derive_session_key(b"psk", b"salt", b"ctx-b");
        assert_ne!(k1, k2);
    }
}
