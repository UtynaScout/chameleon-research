# Phase 2 Checklist (Rust Core)

## Toolchain prerequisites
- [x] Visual Studio Build Tools installed
- [x] `rustc --version` works
- [x] `cargo --version` works
- [x] `cargo test` runs in `rust-core/`

## Code parity goals
- [x] Match frame model semantics with Python generator outputs
- [x] Implement deterministic packet generation path for parity tests
- [x] Add integration fixtures from `data/baseline_v0.3.1.json`
- [x] Модуль frame: завершить реализацию
- [x] Модуль weaver: порт из Python (базовая версия)
- [x] Модуль weaver: генерация chaff, статистика сессий, валидация parity
- [x] Модуль crypto: HKDF (RFC 5869) + ChaCha20-Poly1305 (RFC 8439)
- [ ] Модуль transport: QUIC (quinn) + HTTP/2 (h2)
- [x] Интеграционные тесты: Python ≈ Rust по метрикам
- [x] Интеграция: frame + crypto + weaver end-to-end тест
- [ ] Docker-стенд для тестирования

## Фаза 2.1: Crypto Layer — DONE
- [x] `crypto::hkdf` — HKDF-SHA256 (RFC 5869), derive_session_key, rotate_key
- [x] `crypto::cipher` — ChaCha20-Poly1305 AEAD with AAD (RFC 8439)
- [x] `CryptoError` enum
- [x] `frame::ChameleonFrame::encrypt_with_aad` / `decrypt_with_aad` integration
- [x] 7 crypto tests (RFC vectors, roundtrip, wrong key, tampered AAD, nonce reuse, rotation)

## Фаза 2.2: Transport Layer (QUIC + HTTP/2)
- [ ] Интеграция с quinn (QUIC библиотека)
- [ ] HTTP/2 fallback через h2 crate
- [ ] Stealth Handshake (TLS Padding)
- [ ] Connection pooling
- [ ] Multiplexing streams

## Quality gates
- [x] All Rust unit tests pass
- [x] Basic parity metrics script completes without errors
- [x] Update docs with benchmark results and known limitations

## Safety constraints
- [x] Keep scope on synthetic lab benchmarking only
- [x] Do not add stealth/evasion features
- [x] Preserve transparent logging and testability

## Notes
- Added `ChameleonFrame` encode/decode/pad/encrypt/decrypt in `rust-core/src/frame/mod.rs`.
- Added required frame unit tests and integration parity test against synthetic baseline.
- Started Weaver port with Markov transitions and synthetic profile session generation.
- Phase 2.1: Implemented proper HKDF (hkdf crate + sha2) replacing placeholder XOR derivation.
- Phase 2.1: Added ChaCha20-Poly1305 AEAD with AAD via crypto::cipher module.
- Phase 2.1: Integrated crypto into frame module (encrypt_with_aad / decrypt_with_aad).
- Phase 2.1: Added SessionStats, validate_against_python, generate_chaff to weaver engine.
- Phase 2.1: Added end-to-end integration test (weaver→frame→crypto roundtrip).
