# Фаза 2.1: Crypto-Слой — Отчёт о Завершении

## Дата: Март 2026
## Статус: ✅ ЗАВЕРШЕНО (100%)

---

## Сводка Метрик

| Метрика | Значение | Статус |
|---------|----------|--------|
| Всего тестов | 17 | ✅ |
| Crypto тестов | 7 | ✅ |
| Frame тестов | 5 | ✅ |
| Integration тестов | 3 + 2 internal | ✅ |
| cargo build | SUCCESS (dev + release) | ✅ |
| D_KL Parity (Python ↔ Rust) | < 0.1 | ✅ |

---

## Созданные / Изменённые Файлы

| Файл | Назначение | Строк |
|------|------------|-------|
| `src/crypto/hkdf.rs` | HKDF key derivation (RFC 5869) | 46 |
| `src/crypto/cipher.rs` | ChaCha20-Poly1305 AEAD (RFC 8439) | 48 |
| `src/crypto/mod.rs` | Crypto module exports + CryptoError | 17 |
| `tests/crypto_tests.rs` | 7 crypto unit tests | 123 |
| `src/weaver/engine.rs` | Weaver completion (+chaff, stats, validation) | 369 |
| `src/weaver/mod.rs` | Updated exports | 5 |
| `src/frame/mod.rs` | Crypto integration (encrypt_with_aad / decrypt_with_aad) | ~115 |
| `tests/integration_tests.rs` | E2E tests (+2 новых) | 148 |
| `src/lib.rs` | Updated re-exports | 11 |
| `Cargo.toml` | Added hkdf, sha2, aead | 22 |

---

## Криптографические Компоненты

### HKDF (RFC 5869)

```rust
// Derive 256-bit session key from pre-shared key
pub fn derive_session_key(master_psk: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32];

// Rotate key using HKDF with monotonic counter
pub fn rotate_key(current_key: &[u8; 32], counter: u64) -> [u8; 32];
```

- Использует crate `hkdf` v0.12 + `sha2` v0.10
- HKDF-Extract + HKDF-Expand (HMAC-SHA-256)
- Constant-time HMAC comparisons (через `hkdf` crate internals)

### ChaCha20-Poly1305 (RFC 8439)

```rust
// AEAD encryption with associated data
pub fn encrypt(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

// AEAD decryption with tag verification
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
```

- Использует crate `chacha20poly1305` v0.10
- Поддержка AAD (Additional Authenticated Data)
- 128-bit Poly1305 authentication tag

### Frame Integration

```rust
impl ChameleonFrame {
    // New AAD-aware methods delegating to crypto module
    pub fn encrypt_with_aad(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>, FrameError>;
    pub fn decrypt_with_aad(ct: &[u8], key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) -> Result<Self, FrameError>;
}
```

---

## Weaver Completion

Новые компоненты добавленные в `weaver::engine`:

| Функция | Описание |
|---------|----------|
| `generate_chaff(session, ratio)` | Injection шумовых пакетов (Idle-attributed) |
| `calculate_state_distribution(session)` | Эмпирическое распределение состояний |
| `SessionStats::from_packets(packets)` | Агрегатная статистика сессии |
| `validate_against_python(rust, python, threshold)` | D_KL parity validation |
| `compute_dkl(reference, generated, bins)` | Histogram-based KL divergence |

---

## Тесты

### Crypto Tests (7) — `tests/crypto_tests.rs`

| # | Тест | Что проверяет |
|---|------|---------------|
| 1 | `test_hkdf_rfc5869_deterministic` | RFC 5869 Test Case 1 vector match |
| 2 | `test_chacha20_encrypt_decrypt_roundtrip` | Encrypt → decrypt → verify plaintext |
| 3 | `test_key_rotation_uniqueness` | Разные counter → разные ключи |
| 4 | `test_decrypt_wrong_key_fails` | Неправильный ключ → CryptoError |
| 5 | `test_decrypt_tampered_aad_fails` | Изменённый AAD → CryptoError |
| 6 | `test_nonce_reuse_produces_same_ciphertext` | Детерминизм + разный nonce → разный CT |
| 7 | `test_hkdf_empty_info` | Пустой info → валидный ключ |

### Internal Unit Tests (2) — `src/crypto/hkdf.rs`

| # | Тест | Что проверяет |
|---|------|---------------|
| 1 | `deterministic_derivation` | Одинаковые входы → одинаковый ключ |
| 2 | `different_info_yields_different_key` | Разный info → разный ключ |

### Frame Tests (5) — `tests/frame_tests.rs` (без изменений)

| # | Тест | Что проверяет |
|---|------|---------------|
| 1 | `test_frame_encode_decode` | Binary encode → decode roundtrip |
| 2 | `test_chaff_frame` | Chaff frame type handling |
| 3 | `test_pad_to_size` | Padding до целевого размера |
| 4 | `test_encrypt_decrypt` | ChaCha20 encrypt/decrypt roundtrip |
| 5 | `test_frame_type_conversion` | FrameType ↔ u8 conversion |

### Integration Tests (3) — `tests/integration_tests.rs`

| # | Тест | Что проверяет |
|---|------|---------------|
| 1 | `test_python_rust_distribution_parity` | D_KL(Size) < 0.1, D_KL(IAT) < 0.1 |
| 2 | `test_end_to_end_weaver_frame_crypto` | weaver → frame → HKDF → AEAD roundtrip |
| 3 | `test_chaff_injection_preserves_distribution` | Chaff count + timestamp bounds |

---

## Зависимости (Cargo.toml)

```toml
[dependencies]
hkdf = "0.12"
sha2 = "0.10"
chacha20poly1305 = "0.10"
aead = "0.5"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
rand = "0.8"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
```

---

## Команды для Верификации

```powershell
cd rust-core

# Crypto тесты
cargo test --test crypto_tests

# Integration тесты
cargo test --test integration_tests

# Все тесты
cargo test

# Release сборка
cargo build --release
```

---

## Следующий Этап: Фаза 2.2 (Transport Layer)

См. `docs/phase2.2-plan.md`
