use chameleon_core::crypto;

// ---------------------------------------------------------------------------
// 1. HKDF RFC 5869 — deterministic test vectors
// ---------------------------------------------------------------------------

#[test]
fn test_hkdf_rfc5869_deterministic() {
    // RFC 5869 Test Case 1 (adapted — we verify determinism and non-zero output)
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");

    let key = crypto::derive_session_key(&ikm, &salt, &info);

    // Must be deterministic
    let key2 = crypto::derive_session_key(&ikm, &salt, &info);
    assert_eq!(key, key2, "HKDF must be deterministic");

    // RFC 5869 Test Case 1 expected OKM (first 32 bytes):
    let expected = hex_decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
    );
    assert_eq!(&key[..], &expected[..], "Must match RFC 5869 Test Case 1 OKM");
}

// ---------------------------------------------------------------------------
// 2. ChaCha20-Poly1305 RFC 8439 — encrypt/decrypt roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_chacha20_encrypt_decrypt_roundtrip() {
    let key = [0xAA_u8; 32];
    let nonce = [0x01_u8; 12];
    let aad = b"chameleon-protocol-v1";
    let plaintext = b"synthetic traffic payload for research purposes";

    let ciphertext = crypto::encrypt(plaintext, &key, &nonce, aad)
        .expect("encryption must succeed");

    // Ciphertext must differ from plaintext
    assert_ne!(ciphertext, plaintext);

    let recovered = crypto::decrypt(&ciphertext, &key, &nonce, aad)
        .expect("decryption must succeed");

    assert_eq!(recovered, plaintext);
}

// ---------------------------------------------------------------------------
// 3. Key rotation — uniqueness of rotated keys
// ---------------------------------------------------------------------------

#[test]
fn test_key_rotation_uniqueness() {
    let base_key = [0x42_u8; 32];

    let k0 = crypto::rotate_key(&base_key, 0);
    let k1 = crypto::rotate_key(&base_key, 1);
    let k2 = crypto::rotate_key(&base_key, 2);

    // Each counter must produce a different key
    assert_ne!(k0, k1);
    assert_ne!(k1, k2);
    assert_ne!(k0, k2);

    // Must be deterministic
    assert_eq!(k0, crypto::rotate_key(&base_key, 0));
}

// ---------------------------------------------------------------------------
// 4. Decrypt with wrong key — must fail
// ---------------------------------------------------------------------------

#[test]
fn test_decrypt_wrong_key_fails() {
    let key_good = [0x11_u8; 32];
    let key_bad = [0x22_u8; 32];
    let nonce = [0x00_u8; 12];
    let aad = b"test-aad";
    let plaintext = b"secret data";

    let ciphertext = crypto::encrypt(plaintext, &key_good, &nonce, aad)
        .expect("encryption must succeed");

    let result = crypto::decrypt(&ciphertext, &key_bad, &nonce, aad);
    assert!(result.is_err(), "Decryption with wrong key must fail");
}

// ---------------------------------------------------------------------------
// 5. Decrypt with tampered AAD — must fail
// ---------------------------------------------------------------------------

#[test]
fn test_decrypt_tampered_aad_fails() {
    let key = [0x55_u8; 32];
    let nonce = [0x07_u8; 12];
    let aad_good = b"correct-context";
    let aad_bad = b"tampered-context";
    let plaintext = b"authenticated payload";

    let ciphertext = crypto::encrypt(plaintext, &key, &nonce, aad_good)
        .expect("encryption must succeed");

    let result = crypto::decrypt(&ciphertext, &key, &nonce, aad_bad);
    assert!(result.is_err(), "Decryption with tampered AAD must fail");
}

// ---------------------------------------------------------------------------
// 6. Nonce reuse detection — same key + nonce produces same ciphertext
// ---------------------------------------------------------------------------

#[test]
fn test_nonce_reuse_produces_same_ciphertext() {
    let key = [0xBB_u8; 32];
    let nonce = [0x03_u8; 12];
    let aad = b"nonce-test";
    let plaintext = b"deterministic check";

    let ct1 = crypto::encrypt(plaintext, &key, &nonce, aad).unwrap();
    let ct2 = crypto::encrypt(plaintext, &key, &nonce, aad).unwrap();

    // ChaCha20-Poly1305 is deterministic for the same (key, nonce, plaintext, aad).
    // Identical ciphertext proves nonce reuse is observable — callers must avoid it.
    assert_eq!(
        ct1, ct2,
        "Same (key, nonce, plaintext, aad) must yield identical ciphertext — nonce reuse is detectable"
    );

    // A different nonce must produce different ciphertext
    let nonce2 = [0x04_u8; 12];
    let ct3 = crypto::encrypt(plaintext, &key, &nonce2, aad).unwrap();
    assert_ne!(ct1, ct3, "Different nonce must yield different ciphertext");
}

// ---------------------------------------------------------------------------
// 7. HKDF with empty info — must still produce valid key
// ---------------------------------------------------------------------------

#[test]
fn test_hkdf_empty_info() {
    let key = crypto::derive_session_key(b"master-key", b"salt", b"");
    // Must produce a non-zero 32-byte key
    assert_ne!(key, [0u8; 32]);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
