# API Reference

Документация публичного API crate `chameleon_core`.

> Для интерактивной документации: `cargo doc --no-deps --open`

---

## Содержание

- [Re-exports (lib.rs)](#re-exports)
- [Frame Module](#frame-module)
- [Crypto Module](#crypto-module)
- [Weaver Module](#weaver-module)
- [Transport Module](#transport-module)

---

## Re-exports

Все основные типы доступны через корень crate:

```rust
use chameleon_core::{
    // Frame
    ChameleonFrame, FrameType, TrafficFrame,
    // Crypto
    CryptoError, encrypt, decrypt, derive_session_key, rotate_key,
    // Transport
    Transport, TransportConfig, TransportError, TransportMode,
    // Weaver
    WeaverEngine, WeaverProfile, WeaverState,
    GeneratedPacket, SessionStats,
    ValidationError, validate_against_python,
};
```

---

## Frame Module

### `FrameType`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    Data,     // 0x00
    Ack,      // 0x01
    Control,  // 0x02
    Chaff,    // 0x03
}
```

Конвертации: `From<FrameType> for u8`, `TryFrom<u8> for FrameType`.

### `TrafficFrame`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficFrame {
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}
```

| Метод | Описание |
|-------|----------|
| `payload_len() -> usize` | Длина payload в байтах |

### `ChameleonFrame`

Основной тип для работы с фреймами протокола — кодирование, декодирование, шифрование.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChameleonFrame {
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}
```

#### Wire Format

```
[stream_id: 4 bytes BE][frame_type: 1 byte][payload_len: 4 bytes BE][payload: N bytes]
```

#### Методы

| Метод | Описание |
|-------|----------|
| `encode() -> Vec<u8>` | Сериализация в wire format |
| `decode(input: &[u8]) -> Result<Self, FrameError>` | Десериализация из wire format |
| `pad_to_size(target: usize)` | Дополнить payload нулями до `target` байт |
| `encrypt(key, nonce) -> Result<Vec<u8>, FrameError>` | Шифрование (без AAD) |
| `decrypt(ciphertext, key, nonce) -> Result<Self, FrameError>` | Дешифрование (без AAD) |
| `encrypt_with_aad(key, nonce, aad) -> Result<Vec<u8>, FrameError>` | Шифрование с AAD |
| `decrypt_with_aad(ciphertext, key, nonce, aad) -> Result<Self, FrameError>` | Дешифрование с AAD |

#### Пример

```rust
use chameleon_core::{ChameleonFrame, FrameType};
use chameleon_core::crypto::derive_session_key;

// Создание фрейма
let frame = ChameleonFrame {
    stream_id: 1,
    frame_type: FrameType::Data,
    payload: b"hello world".to_vec(),
};

// Encode/Decode
let wire = frame.encode();
let decoded = ChameleonFrame::decode(&wire).unwrap();
assert_eq!(frame, decoded);

// Encrypt/Decrypt с AAD
let key = derive_session_key(b"my-psk", b"salt", b"info");
let nonce = [0x01; 12];
let aad = b"my-context";

let ciphertext = frame.encrypt_with_aad(&key, &nonce, aad).unwrap();
let decrypted = ChameleonFrame::decrypt_with_aad(&ciphertext, &key, &nonce, aad).unwrap();
assert_eq!(frame, decrypted);
```

### `FrameError`

```rust
#[derive(Debug, Error)]
pub enum FrameError {
    TooShort,
    InvalidFrameType,
    InvalidPayloadLength,
    EncryptionFailed,
    DecryptionFailed,
}
```

---

## Crypto Module

### `derive_session_key`

Выводит 256-битный сессионный ключ из pre-shared key по схеме HKDF (RFC 5869, HMAC-SHA-256).

```rust
pub fn derive_session_key(
    master_psk: &[u8],  // Pre-shared key material (IKM)
    salt: &[u8],        // Random salt (рекомендуется)
    info: &[u8],        // Context-specific info string
) -> [u8; 32]
```

**Пример:**

```rust
use chameleon_core::derive_session_key;

let key = derive_session_key(b"my-secret-psk", b"random-salt", b"session-v1");
assert_eq!(key.len(), 32);

// Детерминированный — одинаковые входы дают одинаковый ключ
let key2 = derive_session_key(b"my-secret-psk", b"random-salt", b"session-v1");
assert_eq!(key, key2);
```

### `rotate_key`

Ротация ключа через HKDF с монотонным счётчиком. Каждое значение счётчика даёт уникальный ключ.

```rust
pub fn rotate_key(current_key: &[u8; 32], counter: u64) -> [u8; 32]
```

**Пример:**

```rust
use chameleon_core::derive_session_key;
use chameleon_core::crypto::hkdf::rotate_key;

let key = derive_session_key(b"psk", b"salt", b"info");
let rotated_1 = rotate_key(&key, 1);
let rotated_2 = rotate_key(&key, 2);
assert_ne!(rotated_1, rotated_2); // Разные счётчики → разные ключи
```

### `encrypt`

Шифрование через ChaCha20-Poly1305 AEAD (RFC 8439).

```rust
pub fn encrypt(
    plaintext: &[u8],    // Данные для шифрования
    key: &[u8; 32],      // 256-битный ключ
    nonce: &[u8; 12],    // 96-битный nonce (НИКОГДА не переиспользовать с тем же ключом)
    aad: &[u8],          // Additional authenticated data
) -> Result<Vec<u8>, CryptoError>
```

Возвращает `ciphertext || 128-bit Poly1305 tag`.

### `decrypt`

```rust
pub fn decrypt(
    ciphertext: &[u8],   // Результат encrypt()
    key: &[u8; 32],      // Тот же ключ
    nonce: &[u8; 12],    // Тот же nonce
    aad: &[u8],          // Тот же AAD
) -> Result<Vec<u8>, CryptoError>
```

Возвращает оригинальный plaintext или `CryptoError::DecryptionFailed` при несовпадении тега.

**Пример:**

```rust
use chameleon_core::{encrypt, decrypt, derive_session_key};

let key = derive_session_key(b"psk", b"salt", b"info");
let nonce = [0x42; 12];
let aad = b"request-id-123";

let ciphertext = encrypt(b"secret data", &key, &nonce, aad).unwrap();
let plaintext = decrypt(&ciphertext, &key, &nonce, aad).unwrap();
assert_eq!(plaintext, b"secret data");
```

### `CryptoError`

```rust
#[derive(Debug, Error)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,  // Authentication tag mismatch
}
```

---

## Weaver Module

Генератор синтетического трафика на основе Марковских цепей.

### `WeaverState`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeaverState {
    Idle,
    Request,
    Stream,
    Ack,
}
```

### `WeaverProfile`

Профиль трафика: матрица переходов + распределения для каждого состояния.

```rust
#[derive(Debug, Clone)]
pub struct WeaverProfile {
    pub transitions: Vec<(WeaverState, Vec<(WeaverState, f64)>)>,
    pub state_profiles: Vec<(WeaverState, StateProfile)>,
}

#[derive(Debug, Clone)]
pub struct StateProfile {
    pub iat_ms: Vec<f64>,       // Распределение inter-arrival time (мс)
    pub size_bytes: Vec<usize>, // Распределение размеров пакетов
    pub up_prob: f64,           // Вероятность направления "вверх"
}
```

`WeaverProfile::default()` возвращает профиль, калиброванный по эталонному браузерному трафику.

### `WeaverEngine`

```rust
pub struct WeaverEngine { /* ... */ }
```

| Метод | Описание |
|-------|----------|
| `new(profile: WeaverProfile) -> Self` | Создание движка с заданным профилем |
| `default() -> Self` | Движок с профилем по умолчанию |
| `get_next_state() -> WeaverState` | Следующее состояние Марковской цепи |
| `sample_iat(state: WeaverState) -> f64` | Сэмплирование IAT для состояния |
| `generate_session(duration_sec: f64) -> Vec<GeneratedPacket>` | Генерация сессии заданной длительности |
| `generate_packets(count: usize) -> Vec<GeneratedPacket>` | Генерация фиксированного числа пакетов |
| `generate_chaff(session, ratio) -> Vec<GeneratedPacket>` | Инъекция chaff-пакетов (шума) |
| `calculate_state_distribution(session) -> HashMap<WeaverState, f64>` | Эмпирическое распределение состояний |

### `GeneratedPacket`

```rust
#[derive(Debug, Clone)]
pub struct GeneratedPacket {
    pub timestamp_sec: f64,   // Абсолютное время
    pub state: WeaverState,   // Состояние генератора
    pub iat_ms: f64,          // Inter-arrival time (мс)
    pub size_bytes: usize,    // Размер пакета
    pub direction_up: bool,   // Направление: true = upload
}
```

### `SessionStats`

```rust
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub packet_sizes: Vec<f64>,
    pub iat_ms: Vec<f64>,
    pub up_ratio: f64,
    pub packet_count: usize,
}
```

| Метод | Описание |
|-------|----------|
| `from_packets(packets: &[GeneratedPacket]) -> Self` | Построение из сессии |

### `validate_against_python`

Валидация Rust-генерации против Python-эталона по D_KL.

```rust
pub fn validate_against_python(
    rust_stats: &SessionStats,
    python_stats: &SessionStats,
    threshold: f64,
) -> Result<(), Vec<ValidationError>>
```

**Пример полного флоу:**

```rust
use chameleon_core::weaver::{WeaverEngine, WeaverProfile, SessionStats};
use chameleon_core::{ChameleonFrame, FrameType, derive_session_key, encrypt};

// 1. Генерация сессии
let mut engine = WeaverEngine::new(WeaverProfile::default());
let session = engine.generate_session(5.0);
println!("Generated {} packets", session.len());

// 2. Статистика
let stats = SessionStats::from_packets(&session);
println!("Avg size: {:.0} bytes", stats.packet_sizes.iter().sum::<f64>() / stats.packet_count as f64);

// 3. Конвертация в фреймы + шифрование
let key = derive_session_key(b"my-psk", b"salt", b"session");
let nonce = [0x01; 12];

for pkt in &session {
    let frame = ChameleonFrame {
        stream_id: 0,
        frame_type: FrameType::Data,
        payload: vec![0u8; pkt.size_bytes],
    };
    let encrypted = frame.encrypt_with_aad(&key, &nonce, b"my-aad").unwrap();
    // ... отправить через transport
}
```

---

## Transport Module

### `TransportMode`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Quic,   // UDP-based QUIC (предпочтительный)
    Http2,  // TCP-based HTTP/2 (fallback)
    Auto,   // QUIC → HTTP/2 при ошибке
}
```

### `TransportConfig`

```rust
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub mode: TransportMode,            // Default: Auto
    pub mtu: usize,                     // Default: 1200
    pub max_connections: usize,         // Default: 8
    pub idle_timeout_ms: u64,           // Default: 30_000
    pub handshake_timeout_ms: u64,      // Default: 5_000
}
```

### `Transport` (Unified API)

Унифицированный транспорт с встроенным шифрованием фреймов.

```rust
pub struct Transport { /* ... */ }
```

| Метод | Описание |
|-------|----------|
| `new(config: TransportConfig, crypto_key: [u8; 32]) -> Self` | Создание с конфигурацией и ключом |
| `connect(addr, server_name).await -> Result<(), TransportError>` | Подключение к серверу |
| `send_frame(frame, nonce, aad).await -> Result<(), TransportError>` | Шифрование + отправка фрейма |
| `send_raw(data).await -> Result<(), TransportError>` | Отправка сырых байт |
| `active_mode() -> TransportMode` | Текущий активный режим |
| `crypto_key() -> &[u8; 32]` | Текущий ключ шифрования |
| `close()` | Закрытие соединения |

**Пример:**

```rust
use chameleon_core::{
    Transport, TransportConfig, TransportMode,
    ChameleonFrame, FrameType, derive_session_key,
};

let key = derive_session_key(b"psk", b"salt", b"session");
let config = TransportConfig {
    mode: TransportMode::Quic,
    ..Default::default()
};

let mut transport = Transport::new(config, key);
transport.connect("127.0.0.1:4433".parse().unwrap(), "localhost").await?;

let frame = ChameleonFrame {
    stream_id: 1,
    frame_type: FrameType::Data,
    payload: b"hello".to_vec(),
};
transport.send_frame(&frame, &[0x01; 12], b"aad").await?;
transport.close();
```

### `QuicTransport`

Низкоуровневый QUIC-транспорт (quinn).

```rust
pub struct QuicTransport { /* ... */ }
```

| Метод | Описание |
|-------|----------|
| `new(config: TransportConfig) -> Self` | Создание клиента |
| `bind_client().await -> Result<(), TransportError>` | Привязка клиентского endpoint |
| `bind_server(addr).await -> Result<(Endpoint, SelfSignedCert), TransportError>` | Привязка серверного endpoint |
| `connect(addr, server_name).await -> Result<(), TransportError>` | QUIC handshake |
| `send(data).await -> Result<(), TransportError>` | Отправка по bi-stream |
| `recv(conn).await -> Result<Vec<u8>, TransportError>` | Чтение входящего bi-stream |
| `close()` | Закрытие |
| `connection() -> Option<&quinn::Connection>` | Внутреннее QUIC-соединение |
| `mtu() -> usize` | Сконфигурированный MTU |

### `Http2Transport` / `Http2Server`

HTTP/2 fallback для сред, блокирующих UDP.

```rust
// Клиент
pub struct Http2Transport { /* ... */ }
pub struct Http2ClientConnection { /* ... */ }

// Сервер (для тестирования)
pub struct Http2Server { /* ... */ }
```

| Тип | Метод | Описание |
|-----|-------|----------|
| `Http2Transport` | `new(config) -> Self` | Создание |
| `Http2Transport` | `connect(addr, server_name).await -> Result<Http2ClientConnection, ..>` | Подключение |
| `Http2ClientConnection` | `send(data).await -> Result<Vec<u8>, ..>` | POST-запрос, возврат ответа |
| `Http2Server` | `bind(addr).await -> Result<Self, ..>` | Привязка TCP listener |
| `Http2Server` | `local_addr() -> Result<SocketAddr, ..>` | Локальный адрес |
| `Http2Server` | `accept_and_echo().await -> Result<Vec<u8>, ..>` | Принять и echo обратно |

### TLS / Handshake Utilities

```rust
// Самоподписанный сертификат
pub struct SelfSignedCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

pub fn generate_self_signed() -> Result<SelfSignedCert, String>
pub fn client_crypto_config() -> rustls::ClientConfig       // QUIC (ALPN: h3)
pub fn server_config() -> Result<(quinn::ServerConfig, SelfSignedCert), String>
pub fn client_crypto_config_h2() -> rustls::ClientConfig    // HTTP/2 (ALPN: h2)
pub fn server_tls_config_h2() -> Result<(rustls::ServerConfig, SelfSignedCert), String>
```

> **Примечание:** `InsecureServerVerifier` используется для тестовых self-signed сертификатов.
> В продакшене замените на верификацию через CA.

### `TransportError`

```rust
#[derive(Debug, Error)]
pub enum TransportError {
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    HandshakeFailed(String),
    Timeout,
    PoolExhausted { max: usize },
}
```
