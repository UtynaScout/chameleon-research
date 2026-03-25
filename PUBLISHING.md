# Publishing Guide

Руководство по публикации NetSynth Lab v1.0.0.

---

## Pre-Flight Checks

```bash
cd rust-core

# 1. Все тесты
cargo test
# Expected: 37 passed (30 original + 7 network)

# 2. Release build
cargo build --release
# Expected: 0 warnings

# 3. Документация
cargo doc --no-deps
# Expected: no errors

# 4. Примеры
cargo run --example server -- --help
cargo run --example client -- --help

# 5. Бенчмарки
cargo bench
# Expected: all benchmarks complete

# 6. Dry-run publish
cargo publish --dry-run
```

---

## GitHub Release

### 1. Создание Tag

```bash
git tag -a v1.0.0 -m "Release v1.0.0 — NetSynth Lab"
git push origin main
git push origin v1.0.0
```

### 2. GitHub Release (через UI)

1. Перейти на https://github.com/<owner>/chameleon-research/releases/new
2. Выбрать tag `v1.0.0`
3. Заголовок: `NetSynth Lab v1.0.0`
4. Описание (скопировать из CHANGELOG.md секцию `[1.0.0]`)
5. Прикрепить бинарники (из `target/release/`)
6. Нажать **Publish release**

### 3. GitHub Release (через CLI)

```bash
# Установить GitHub CLI: https://cli.github.com/
gh release create v1.0.0 \
    --title "NetSynth Lab v1.0.0" \
    --notes-file CHANGELOG.md \
    rust-core/target/release/examples/server \
    rust-core/target/release/examples/client
```

---

## crates.io Publication

### 1. Первоначальная Настройка

```bash
# Получить API token: https://crates.io/settings/tokens
cargo login <your-api-token>
```

### 2. Подготовка Cargo.toml

Убедитесь, что в `Cargo.toml` заполнены обязательные поля:

```toml
[package]
name = "chameleon-core"
version = "1.0.0"
edition = "2021"
description = "Network traffic synthesis laboratory — research platform for synthetic traffic generation"
license = "MIT"
repository = "https://github.com/<owner>/chameleon-research"
documentation = "https://docs.rs/chameleon-core"
readme = "../README.md"
keywords = ["network", "traffic", "synthesis", "research", "quic"]
categories = ["network-programming", "simulation"]
```

### 3. Проверка и Публикация

```bash
# Проверка пакета
cargo package

# Dry-run (не публикует)
cargo publish --dry-run

# Публикация
cargo publish
```

### 4. Верификация

```bash
# Проверка на crates.io
# Перейти: https://crates.io/crates/chameleon-core

# Проверка docs.rs
# Перейти: https://docs.rs/chameleon-core

# Установка из crates.io
cargo install chameleon-core
```

---

## Build Artifacts

### Сборка для Всех Платформ

```bash
# Linux x86_64
cargo build --release --target x86_64-unknown-linux-gnu

# Windows x86_64
cargo build --release --target x86_64-pc-windows-msvc

# macOS x86_64
cargo build --release --target x86_64-apple-darwin

# macOS ARM (M1/M2)
cargo build --release --target aarch64-apple-darwin
```

### Упаковка

```bash
# Linux
tar -czf netsynth-v1.0.0-linux-x64.tar.gz \
    -C target/release examples/server examples/client chameleon-core

# Windows
Compress-Archive -Path target\release\examples\server.exe, `
    target\release\examples\client.exe, `
    target\release\chameleon-core.exe `
    -DestinationPath netsynth-v1.0.0-windows-x64.zip
```

---

## CI/CD

GitHub Actions автоматически:
1. Запускает тесты на push/PR (ubuntu, windows, macos)
2. Запускает бенчмарки
3. Создаёт GitHub Release при push tag `v*`

Файл: `.github/workflows/ci.yml`

---

## Post-Release Checklist

- [ ] Проверить GitHub Release опубликован
- [ ] Проверить crates.io страницу
- [ ] Проверить docs.rs документацию
- [ ] Обновить PROJECT_ROADMAP.md
- [ ] Создать ветку `develop` для дальнейшей разработки
