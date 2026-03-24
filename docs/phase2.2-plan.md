# Фаза 2.2: Transport Layer — План Реализации

## Статус: 📅 Планирование
## Предусловия: Фаза 2.1 (Crypto) ✅

---

## Архитектура

```
transport/
├── mod.rs          — TransportConfig, TransportMode, re-exports
├── quic.rs         — QUIC transport (quinn crate)
├── http2.rs        — HTTP/2 fallback (h2 crate)
└── handshake.rs    — TLS handshake + padding logic
```

### Поток Данных

```
WeaverEngine::generate_session()
    │
    ▼
ChameleonFrame::encode()
    │
    ▼
crypto::encrypt(frame, session_key, nonce, aad)
    │
    ▼
Transport::send(encrypted_frame)
    ├─ QuicTransport   (UDP, 0-RTT, multiplexing)
    └─ Http2Transport  (TCP fallback, TLS 1.3)
```

---

## Выбор Библиотек

| Библиотека | Версия | Назначение | Обоснование |
|------------|--------|------------|-------------|
| `quinn` | 0.11 | QUIC transport | Наиболее зрелая Rust QUIC реализация, async |
| `rustls` | 0.23 | TLS backend | Чистый Rust, без OpenSSL зависимости |
| `rcgen` | 0.13 | Self-signed certs | Генерация тестовых сертификатов |
| `h2` | 0.4 | HTTP/2 framing | Низкоуровневый HTTP/2, без HTTP overhead |
| `tokio` | 1.x | Async runtime | Уже используется, расширяем features |

> **Примечание:** Версии выбраны для совместимости rustls 0.23 + quinn 0.11 ecosystem.
> `ring` не добавляется отдельно — поставляется как transitive через `rustls`.

---

## План Реализации

### Этап 1: QUIC Transport (~2-3 дня)

1. **`transport/quic.rs` — Базовый клиент/сервер**
   - `QuicTransport` struct с `quinn::Endpoint`
   - `connect(addr) -> QuicConnection`
   - `send_frame(connection, encrypted_bytes)`
   - `receive_frame(connection) -> Vec<u8>`
   - Self-signed TLS config для тестирования

2. **Connection Lifecycle**
   - Установка соединения с retry логикой
   - Graceful shutdown
   - Timeout настройки (idle, handshake, keep-alive)

3. **Multiplexing**
   - Каждый `stream_id` маппится на QUIC stream
   - Bidirectional streams для Data/Ack
   - Unidirectional streams для Control/Chaff

### Этап 2: HTTP/2 Fallback (~1-2 дня)

1. **`transport/http2.rs` — TCP fallback**
   - `Http2Transport` struct
   - `connect(addr) -> Http2Connection`
   - Framing через h2 с binary payload
   - TLS 1.3 via rustls

2. **Fallback Logic**
   - Попытка QUIC → если UDP заблокирован → fallback на HTTP/2
   - `TransportMode::Auto` для автоматического выбора

### Этап 3: Handshake & Padding (~1 день)

1. **`transport/handshake.rs` — TLS Padding**
   - Padding ClientHello до стандартных размеров
   - ALPN configuration (h3 для QUIC, h2 для HTTP/2)
   - SNI handling

### Этап 4: Connection Pooling (~1 день)

1. **Pool Manager**
   - Пул соединений с ограничением (max_connections)
   - Переиспользование idle connections
   - Health checks

---

## API Design

```rust
/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub mode: TransportMode,
    pub mtu: usize,
    pub max_connections: usize,
    pub idle_timeout_ms: u64,
    pub handshake_timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Quic,       // UDP-based QUIC
    Http2,      // TCP-based HTTP/2
    Auto,       // Try QUIC, fallback to HTTP/2
}

/// Unified transport trait
#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&mut self, addr: &str) -> Result<(), TransportError>;
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    async fn recv(&mut self) -> Result<Vec<u8>, TransportError>;
    async fn close(&mut self) -> Result<(), TransportError>;
}

/// QUIC transport implementation
pub struct QuicTransport { ... }
impl Transport for QuicTransport { ... }

/// HTTP/2 transport implementation
pub struct Http2Transport { ... }
impl Transport for Http2Transport { ... }
```

---

## Критерии Готовности

- [ ] `QuicTransport` — connect/send/recv/close
- [ ] `Http2Transport` — connect/send/recv/close
- [ ] Handshake padding implementation
- [ ] Connection pooling (max_connections limit)
- [ ] Multiplexing (multiple streams per connection)
- [ ] Fallback logic (QUIC → HTTP/2)
- [ ] 5+ transport тестов passing
- [ ] Integration test: weaver → frame → crypto → transport roundtrip
- [ ] `cargo build --release` без ошибок
- [ ] Документация публичных API

---

## Тесты

### Transport Tests — `tests/transport_tests.rs`

| # | Тест | Что проверяет |
|---|------|---------------|
| 1 | `test_quic_connect_send_recv` | QUIC loopback: connect → send → recv |
| 2 | `test_http2_connect_send_recv` | HTTP/2 loopback: connect → send → recv |
| 3 | `test_transport_fallback` | QUIC fail → automatic HTTP/2 fallback |
| 4 | `test_connection_pool_limit` | Pool does not exceed max_connections |
| 5 | `test_multiplexed_streams` | Multiple streams on single connection |
| 6 | `test_handshake_padding` | ClientHello padded to standard size |
| 7 | `test_end_to_end_pipeline` | weaver → frame → crypto → transport → decrypt → verify |

---

## Интеграция с Существующими Модулями

### Frame Module
- `ChameleonFrame` → `encode()` → `encrypt_with_aad()` → `Transport::send()`
- `Transport::recv()` → `decrypt_with_aad()` → `ChameleonFrame::decode()`

### Crypto Module
- Session key derived via `crypto::derive_session_key()`
- Key rotation via `crypto::rotate_key()` после каждых N пакетов
- Nonce management: counter-based nonce derivation per stream

### Weaver Module
- `WeaverEngine` генерирует `GeneratedPacket` stream
- Каждый пакет конвертируется в `ChameleonFrame`
- Timing (iat_ms) контролирует `tokio::time::sleep` между отправками

---

## Риски и Митигация

| Риск | Вероятность | Митигация |
|------|-------------|-----------|
| quinn API изменения | Средняя | Pin exact version, проверить changelog |
| UDP блокировка в тестах | Высокая | Loopback (127.0.0.1), fallback тесты |
| TLS certificate setup | Средняя | rcgen для self-signed, отдельный test fixture |
| Async complexity | Средняя | Использовать tokio test runtime |
