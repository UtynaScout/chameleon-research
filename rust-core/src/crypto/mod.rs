use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key material")]
    InvalidKeyMaterial,
}

pub fn derive_session_key(master_psk: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    if master_psk.is_empty() || salt.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let mut key = [0_u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        let p = master_psk[idx % master_psk.len()];
        let s = salt[idx % salt.len()];
        *byte = p ^ s ^ (idx as u8);
    }
    Ok(key)
}
