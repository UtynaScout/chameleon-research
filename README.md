# NetSynth Lab

[![Tests](https://img.shields.io/badge/tests-30%20passing-brightgreen)]()
[![Build](https://img.shields.io/badge/build-zero%20warnings-brightgreen)]()
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

**Network Traffic Synthesis Laboratory** — исследовательская платформа для генерации
синтетического сетевого трафика с настраиваемыми статистическими профилями.

## ⚠️ Этическое Использование

Этот проект предназначен **исключительно** для:
- Научных исследований в области сетевого анализа
- Тестирования систем мониторинга и классификации трафика
- Образовательных целей

**Запрещено** использование для обхода систем безопасности без разрешения.

---

## Назначение

- Генерация синтетического трафика с заданными статистическими профилями (размеры пакетов, inter-arrival times)
- Оценка качества генерации через метрики KL-дивергенции, JS-дивергенции, расстояние Wasserstein
- Сквозное шифрование через HKDF + ChaCha20-Poly1305 (RFC 5869 / RFC 8439)
- Транспорт через QUIC (primary) и HTTP/2 (fallback)

## Быстрый Старт

### Требования

- **Rust** 1.70+ (рекомендуется 1.94+)
- **Python** 3.10+ (для симулятора)
- Windows / Linux / macOS

### Сборка Rust-ядра

```bash
cd rust-core
cargo build --release
```

### Запуск Тестов

```bash
cd rust-core
cargo test
```

### Запуск Сервера (QUIC echo)

```bash
cargo run --example server -- --port 4433
```

### Запуск Клиента (Weaver traffic generator)

```bash
cargo run --example client -- --server 127.0.0.1:4433 --duration 10
```

### Python-Симулятор

```bash
python -m venv .venv
# Windows:
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

pip install -r python-simulator/requirements.txt
python python-simulator/meta_profile_generator_v2.py
```

## Метрики Качества

| Метрика | Значение | Порог |
|---------|----------|-------|
| D_KL (Size) | 0.0348 | < 0.05 |
| D_KL (IAT) | 0.0670 | < 0.10 |
| Тесты | 30 passing | — |
| Warnings | 0 | — |

## Архитектура

```
chameleon-research/
├── python-simulator/          # Python-прототип + эталонные метрики
│   ├── meta_profile_generator_v2.py
│   ├── metrics_calculator.py
│   └── reference_extractor.py
│
├── rust-core/                 # Основное Rust-ядро
│   ├── src/
│   │   ├── lib.rs             # Публичное API
│   │   ├── frame/             # Frame encode/decode/encrypt/decrypt
│   │   ├── weaver/            # Markov-chain traffic generator
│   │   ├── crypto/            # HKDF + ChaCha20-Poly1305
│   │   └── transport/         # QUIC + HTTP/2 + TLS handshake
│   ├── examples/
│   │   ├── server.rs          # QUIC echo server с CLI
│   │   └── client.rs          # QUIC client + Weaver генерация
│   └── tests/
│       ├── crypto_tests.rs    # 7 тестов
│       ├── frame_tests.rs     # 5 тестов
│       ├── transport_tests.rs # 7 тестов
│       ├── e2e_tests.rs       # 6 тестов
│       └── integration_tests.rs # 3 теста + 2 unit
│
├── configs/                   # Профили трафика (JSON)
├── data/                      # Baseline данные и статистика
└── docs/                      # Документация
    ├── API.md                 # API reference
    ├── DEPLOYMENT.md          # Руководство по развёртыванию
    ├── RELEASE-CHECKLIST.md   # Чек-лист релиза
    ├── e2e-test-plan.md       # План E2E тестирования
    ├── architecture.md        # Архитектура системы
    └── development-guide.md   # Руководство разработчика
```

## Тестирование

```bash
# Все 30 тестов
cargo test

# По отдельности
cargo test --test crypto_tests       # HKDF + ChaCha20 (7 тестов)
cargo test --test frame_tests        # Frame encode/decode (5 тестов)
cargo test --test transport_tests    # QUIC + HTTP/2 (7 тестов)
cargo test --test e2e_tests          # End-to-End (6 тестов)
cargo test --test integration_tests  # Weaver + Crypto + Parity (3 теста)

# Генерация rustdoc
cargo doc --no-deps --open
```

## Документация

- [API Reference](docs/API.md) — полное описание публичного API
- [Deployment Guide](docs/DEPLOYMENT.md) — руководство по развёртыванию
- [Release Checklist](docs/RELEASE-CHECKLIST.md) — чек-лист для релиза
- [E2E Test Plan](docs/e2e-test-plan.md) — план сквозного тестирования
- [Architecture](docs/architecture.md) — архитектура системы
- [Development Guide](docs/development-guide.md) — руководство разработчика
- [Changelog](CHANGELOG.md) — история изменений

## Лицензия

MIT License — см. [LICENSE](LICENSE).

## Безопасность

Все криптографические примитивы реализованы в соответствии с RFC:
- **HKDF** — RFC 5869 (HMAC-SHA-256)
- **ChaCha20-Poly1305** — RFC 8439 (AEAD)
- **TLS 1.3** — для QUIC и HTTP/2 transport
- Constant-time операции через `hkdf` и `chacha20poly1305` crates
