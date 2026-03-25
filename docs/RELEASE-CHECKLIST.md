# Release Checklist — v1.0.0

## Pre-Release

- [x] Все тесты passing (`cargo test` — 30 passed)
- [x] `cargo build --release` без предупреждений
- [x] `cargo clippy` без ошибок (если применимо)
- [ ] README.md обновлён и соответствует текущему API
- [ ] API документация (docs/API.md) покрывает все публичные типы
- [ ] CHANGELOG.md заполнен
- [ ] Версия в Cargo.toml обновлена до `1.0.0`
- [ ] Все TODO/FIXME в коде разрешены или задокументированы
- [ ] Лицензия (LICENSE файл) присутствует в корне проекта

## Тестирование

- [x] Unit-тесты (2 passed)
- [x] Crypto-тесты (7 passed)
- [x] Frame-тесты (5 passed)
- [x] Integration-тесты (3 passed)
- [x] Transport-тесты (7 passed)
- [x] E2E-тесты на localhost (6 passed)
- [ ] E2E-тесты в реальной LAN-сети
- [ ] E2E-тесты через WAN
- [ ] Стресс-тест (100+ одновременных соединений)
- [ ] Long-running тест (1 час+ непрерывной работы)
- [ ] Тест на разных ОС (Windows / Linux / macOS)

## Документация

- [ ] README.md — описание, quick start, архитектура
- [ ] docs/API.md — полный API reference
- [ ] docs/DEPLOYMENT.md — руководство по развёртыванию
- [ ] docs/e2e-test-plan.md — план E2E тестирования
- [ ] docs/architecture.md — архитектура системы
- [ ] docs/development-guide.md — руководство разработчика
- [ ] CHANGELOG.md — история изменений
- [ ] `cargo doc --no-deps` — rustdoc генерируется без ошибок

## Примеры

- [x] `examples/server.rs` компилируется и запускается (`--help`)
- [x] `examples/client.rs` компилируется и запускается (`--help`)
- [ ] Server + Client взаимодействуют корректно (ручной тест)

## Безопасность

- [x] RFC 5869 compliance (HKDF)
- [x] RFC 8439 compliance (ChaCha20-Poly1305)
- [x] TLS 1.3 для QUIC и HTTP/2
- [x] Этический disclaimer в README.md
- [x] Self-signed сертификаты помечены как тестовые
- [ ] Аудит зависимостей (`cargo audit`, если установлен)

## Release

- [ ] Git tag `v1.0.0` создан
- [ ] `git push origin main`
- [ ] `git push origin v1.0.0`
- [ ] GitHub Release создан с описанием и бинарниками
- [ ] crates.io публикация (`cargo publish`)
- [ ] Бинарные артефакты для Windows/Linux/macOS (опционально)

## Post-Release

- [ ] Проверка установки: `cargo install chameleon-core`
- [ ] Проверка `cargo doc` на docs.rs
- [ ] Анонс в сообществе (если применимо)
- [ ] Обновление PROJECT_ROADMAP.md

---

## Команды для Верификации

```bash
# Полный набор проверок перед релизом
cd rust-core

# 1. Тесты
cargo test

# 2. Release-сборка
cargo build --release

# 3. Документация
cargo doc --no-deps

# 4. Примеры
cargo run --example server -- --help
cargo run --example client -- --help

# 5. Tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin main
git push origin v1.0.0
```
