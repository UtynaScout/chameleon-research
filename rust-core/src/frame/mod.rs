pub mod model;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use thiserror::Error;

use self::model::FrameType;

#[derive(Debug, Error)]
pub enum FrameError {
	#[error("frame too short")]
	TooShort,
	#[error("invalid frame type")]
	InvalidFrameType,
	#[error("invalid payload length")]
	InvalidPayloadLength,
	#[error("encryption failed")]
	EncryptionFailed,
	#[error("decryption failed")]
	DecryptionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChameleonFrame {
	pub stream_id: u32,
	pub frame_type: FrameType,
	pub payload: Vec<u8>,
}

impl ChameleonFrame {
	pub fn encode(&self) -> Vec<u8> {
		let mut encoded = Vec::with_capacity(9 + self.payload.len());
		encoded.extend_from_slice(&self.stream_id.to_be_bytes());
		encoded.push(u8::from(self.frame_type));
		encoded.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
		encoded.extend_from_slice(&self.payload);
		encoded
	}

	pub fn decode(input: &[u8]) -> Result<Self, FrameError> {
		if input.len() < 9 {
			return Err(FrameError::TooShort);
		}

		let stream_id = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
		let frame_type = FrameType::try_from(input[4]).map_err(|_| FrameError::InvalidFrameType)?;
		let payload_len = u32::from_be_bytes([input[5], input[6], input[7], input[8]]) as usize;
		let payload_start = 9;
		let payload_end = payload_start + payload_len;

		if payload_end > input.len() {
			return Err(FrameError::InvalidPayloadLength);
		}

		Ok(Self {
			stream_id,
			frame_type,
			payload: input[payload_start..payload_end].to_vec(),
		})
	}

	pub fn pad_to_size(&mut self, target: usize) {
		let current_size = self.encode().len();
		if target <= current_size {
			return;
		}

		let required = target - current_size;
		self.payload.resize(self.payload.len() + required, 0_u8);
	}

	/// Encrypt (no AAD) — backward-compatible helper.
	pub fn encrypt(&self, key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, FrameError> {
		let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
		let nonce = Nonce::from_slice(nonce);
		cipher
			.encrypt(nonce, self.encode().as_ref())
			.map_err(|_| FrameError::EncryptionFailed)
	}

	/// Decrypt (no AAD) — backward-compatible helper.
	pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Self, FrameError> {
		let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
		let nonce = Nonce::from_slice(nonce);
		let plaintext = cipher
			.decrypt(nonce, ciphertext)
			.map_err(|_| FrameError::DecryptionFailed)?;
		Self::decode(&plaintext)
	}

	/// Encrypt with associated data via the `crypto` module.
	pub fn encrypt_with_aad(
		&self,
		key: &[u8; 32],
		nonce: &[u8; 12],
		aad: &[u8],
	) -> Result<Vec<u8>, FrameError> {
		crate::crypto::encrypt(&self.encode(), key, nonce, aad)
			.map_err(|_| FrameError::EncryptionFailed)
	}

	/// Decrypt with associated data via the `crypto` module.
	pub fn decrypt_with_aad(
		ciphertext: &[u8],
		key: &[u8; 32],
		nonce: &[u8; 12],
		aad: &[u8],
	) -> Result<Self, FrameError> {
		let plaintext = crate::crypto::decrypt(ciphertext, key, nonce, aad)
			.map_err(|_| FrameError::DecryptionFailed)?;
		Self::decode(&plaintext)
	}
}
