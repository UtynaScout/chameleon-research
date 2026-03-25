# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.1.0] — 2026-03-25

### Added

**VPN TUN/TAP Module (Phase 5.0)**
- `src/tun/mod.rs` — TUN device abstraction (Linux via /dev/net/tun ioctl, non-Linux stubs)
- `src/tun/route.rs` — OS-level route management (ip route, iptables NAT, ip_forward)
- `VpnTunnel` — encrypted bidirectional QUIC tunnel with ChaCha20-Poly1305
- `VpnTunnelSender` / `VpnTunnelReceiver` — split halves for concurrent relay
- Counter-based nonce scheme with direction byte (12-byte: [4B direction LE][8B counter LE])
- Wire format: `[2B length BE][encrypted IP packet]` on persistent QUIC bi-stream
- Cross-platform compilation: Linux TUN + non-Linux stubs returning `TunError::Unsupported`

**VPN Examples**
- `examples/vpn-server.rs` — multi-client server with TUN, IP forwarding, NAT masquerade
- `examples/vpn-client.rs` — client with TUN, route management, bidirectional relay
- Auto-learn client IPs from IPv4 source header (no assignment protocol needed)
- TOML config file support (`--config` flag)
- Graceful Ctrl+C shutdown with NAT/route cleanup

**Configuration & Docker**
- `configs/vpn-server.toml` — server configuration template
- `configs/vpn-client.toml` — client configuration template
- `docker/Dockerfile.server` — multi-stage Docker build for server
- `docker/Dockerfile.client` — multi-stage Docker build for client
- `docker/docker-compose.yml` — orchestration with NET_ADMIN + /dev/net/tun

**Documentation & Tests**
- `docs/VPN-SETUP.md` — complete setup guide (architecture, deployment, troubleshooting)
- 3 new VPN tunnel tests (roundtrip, 100-packet echo, 1400-byte large packet)
- All tests cross-platform (QUIC-only, no TUN/root required)

### Metrics

| Metric | Value |
|--------|-------|
| Tests | 40 passing (+3 new) |
| Warnings | 0 |

### Dependencies
- Added: `libc 0.2` (Linux TUN ioctl), `toml 0.8` (config parsing)

---

## [1.0.0] — 2026-03-25

### Added

**Python Simulator (Phase 1)**
- `meta_profile_generator_v2.py` — генератор трафика на Марковских цепях
- `metrics_calculator.py` — вычисление D_KL, JS-дивергенции, Wasserstein
- `reference_extractor.py` — извлечение эталонной статистики из pcapng
- 4 Python-теста passing

**Rust Core — Frame Module (Phase 2.0)**
- `ChameleonFrame` — encode/decode/pad/encrypt/decrypt
- `FrameType` enum (Data, Ack, Control, Chaff)
- `TrafficFrame` — сериализуемая модель трафика
- Wire format: `[stream_id: 4B][type: 1B][len: 4B][payload]`
- 5 frame-тестов

**Rust Core — Weaver Engine (Phase 2.0)**
- `WeaverEngine` — Марков-генератор сессий с профилями
- `WeaverProfile` — матрица переходов + распределения
- `generate_session(duration)` — генерация по длительности
- `generate_chaff(session, ratio)` — инъекция шумовых пакетов
- `validate_against_python()` — D_KL валидация против Python-эталона
- 3 integration-теста (включая Python–Rust parity)

**Rust Core — Crypto Layer (Phase 2.1)**
- HKDF key derivation (RFC 5869, HMAC-SHA-256)
- ChaCha20-Poly1305 AEAD encryption (RFC 8439)
- Key rotation с монотонным счётчиком
- `encrypt_with_aad` / `decrypt_with_aad` на ChameleonFrame
- 7 crypto-тестов

**Rust Core — Transport Layer (Phase 2.2)**
- QUIC transport через quinn 0.11
- HTTP/2 fallback через h2 0.4
- Unified `Transport` API (connect/send_frame/send_raw/close)
- `TransportMode::Auto` — QUIC с fallback на HTTP/2
- Config-driven MTU, idle timeout, handshake timeout
- Self-signed TLS certificates (lab/test use)
- 7 transport-тестов

**End-to-End Tests (Phase 2.3)**
- `examples/server.rs` — QUIC echo server с CLI (clap) и tracing
- `examples/client.rs` — QUIC client с Weaver-генерацией трафика
- 6 E2E-тестов: localhost roundtrip, D_KL validation, 20 concurrent connections, unified Transport API, HTTP/2 fallback, multi-stream
- `docs/e2e-test-plan.md` — план тестирования

**Documentation (Phase 3.0)**
- Полный README.md с quick start и архитектурой
- `docs/API.md` — полный API reference
- `docs/DEPLOYMENT.md` — руководство по развёртыванию
- `docs/RELEASE-CHECKLIST.md` — чек-лист релиза
- `CHANGELOG.md` — история изменений

### Metrics

| Метрика | Значение |
|---------|----------|
| D_KL (Size) | 0.0348 (порог < 0.05) |
| D_KL (IAT) | 0.0670 (порог < 0.10) |
| Тесты | 30 passing |
| Warnings | 0 |

### Changed
- D_KL(Size) улучшен: 9.24 → 0.0348
- D_KL(IAT) улучшен: 0.74 → 0.0670

### Fixed
- Все предупреждения компилятора устранены
- HTTP/2 connection flush корректно вызывается перед чтением
- QUIC ALPN `h3` / HTTP/2 ALPN `h2` разделены в handshake

### Security
- RFC 5869 compliance для HKDF (HMAC-SHA-256)
- RFC 8439 compliance для ChaCha20-Poly1305
- TLS 1.3 для QUIC и HTTP/2 transport
- Constant-time операции через `hkdf` и `chacha20poly1305` crates
- Этический disclaimer во всей документации

### Dependencies
- serde 1.0, thiserror 1.0, rand 0.8, tokio 1
- chacha20poly1305 0.10, aead 0.5, hkdf 0.12, sha2 0.10
- quinn 0.11, rustls 0.23, rcgen 0.13
- h2 0.4, http 1, bytes 1, tokio-rustls 0.26
- clap 4, tracing 0.1, tracing-subscriber 0.3
