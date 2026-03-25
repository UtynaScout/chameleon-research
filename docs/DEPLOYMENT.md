# Deployment Guide

Руководство по развёртыванию NetSynth Lab.

> ⚠️ Этот проект предназначен **исключительно** для научных исследований,
> тестирования систем мониторинга и образовательных целей.

---

## Системные Требования

| Компонент | Минимум | Рекомендуется |
|-----------|---------|---------------|
| Rust | 1.70+ | 1.94+ |
| Python | 3.10+ | 3.12+ |
| RAM | 2 GB | 4 GB |
| Disk | 500 MB | 1 GB |
| OS | Windows 10+ / Linux 5.4+ / macOS 12+ | — |

### Зависимости ОС

**Windows:**
- Visual Studio Build Tools (MSVC) или MinGW
- Git

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev git
```

**macOS:**
```bash
xcode-select --install
```

---

## Сборка из Исходников

### 1. Клонирование

```bash
git clone <repository-url> chameleon-research
cd chameleon-research
```

### 2. Сборка Rust-ядра

```bash
cd rust-core
cargo build --release
```

Бинарные файлы:
- `target/release/chameleon-core` — основной бинарник
- `target/release/examples/server` — QUIC echo server
- `target/release/examples/client` — QUIC client

### 3. Проверка Сборки

```bash
cargo test
# Ожидается: 30 passed; 0 failed

cargo build --release
# Ожидается: 0 warnings
```

### 4. Python-Симулятор (опционально)

```bash
cd ../python-simulator
python -m venv ../.venv

# Windows:
..\.venv\Scripts\Activate.ps1
# Linux/macOS:
source ../.venv/bin/activate

pip install -r requirements.txt
python meta_profile_generator_v2.py
```

---

## Запуск Сервера

### Базовый Запуск

```bash
cd rust-core
cargo run --release --example server -- --port 4433
```

### Параметры CLI

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `--port` / `-p` | 4433 | Порт для прослушивания |
| `--psk` | `lab-psk` | Pre-shared key для HKDF |

### Примеры

```bash
# Стандартный запуск
cargo run --release --example server

# Кастомный порт и PSK
cargo run --release --example server -- --port 5555 --psk "my-secret-key"
```

### Логирование

Сервер использует `tracing` — уровень логирования через `RUST_LOG`:

```bash
# Детальный лог
RUST_LOG=info cargo run --release --example server

# Debug-уровень
RUST_LOG=debug cargo run --release --example server

# Только предупреждения
RUST_LOG=warn cargo run --release --example server
```

На Windows (PowerShell):
```powershell
$env:RUST_LOG = "info"
cargo run --release --example server
```

---

## Запуск Клиента

### Базовый Запуск

```bash
cargo run --release --example client -- --server 127.0.0.1:4433 --duration 10
```

### Параметры CLI

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `--server` / `-s` | `127.0.0.1:4433` | Адрес сервера (host:port) |
| `--duration` / `-d` | `5.0` | Длительность сессии (секунды) |
| `--psk` | `lab-psk` | Pre-shared key (должен совпадать с сервером) |

### Примеры

```bash
# Короткая сессия (5 секунд)
cargo run --release --example client

# Длинная сессия (60 секунд) на кастомный сервер
cargo run --release --example client -- \
    --server 192.168.1.100:4433 \
    --duration 60 \
    --psk "shared-secret"
```

---

## Развёртывание как Сервис

### Linux (systemd)

1. Скопировать бинарник:
```bash
sudo cp target/release/examples/server /usr/local/bin/netsynth-server
```

2. Создать systemd unit `/etc/systemd/system/netsynth.service`:
```ini
[Unit]
Description=NetSynth Lab QUIC Server
After=network.target

[Service]
Type=simple
User=netsynth
Group=netsynth
Environment="RUST_LOG=info"
ExecStart=/usr/local/bin/netsynth-server --port 4433 --psk "your-psk-here"
Restart=on-failure
RestartSec=5

# Ограничения безопасности
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

3. Запуск:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now netsynth
sudo systemctl status netsynth
```

### Windows (NSSM)

Для запуска как Windows-сервис можно использовать [NSSM](https://nssm.cc/):

```powershell
nssm install NetSynth "C:\path\to\server.exe" "--port 4433 --psk your-psk"
nssm set NetSynth AppEnvironmentExtra "RUST_LOG=info"
nssm start NetSynth
```

---

## Сеть и Firewall

### Порты

| Протокол | Порт | Назначение |
|----------|------|------------|
| UDP | 4433 | QUIC transport (основной) |
| TCP | 4433 | HTTP/2 fallback |

### Firewall

**Linux (ufw):**
```bash
sudo ufw allow 4433/udp comment "NetSynth QUIC"
sudo ufw allow 4433/tcp comment "NetSynth HTTP/2 fallback"
```

**Windows:**
```powershell
New-NetFirewallRule -DisplayName "NetSynth QUIC" -Direction Inbound -Protocol UDP -LocalPort 4433 -Action Allow
New-NetFirewallRule -DisplayName "NetSynth HTTP2" -Direction Inbound -Protocol TCP -LocalPort 4433 -Action Allow
```

---

## Мониторинг

### Логи

Логи выводятся в stdout через `tracing-subscriber`. Для перенаправления в файл:

```bash
RUST_LOG=info netsynth-server --port 4433 2>&1 | tee /var/log/netsynth.log
```

### Проверка Здоровья

Клиент с минимальной сессией для health-check:

```bash
cargo run --release --example client -- --server 127.0.0.1:4433 --duration 1
```

Успешный вывод с ненулевым количеством echo-matched пакетов подтверждает работоспособность.

---

## Безопасность при Развёртывании

1. **PSK** — используйте криптографически стойкий ключ (минимум 32 символа)
2. **TLS** — в продакшене замените self-signed сертификаты на CA-подписанные
3. **Сеть** — ограничьте доступ к серверу по IP через firewall
4. **Пользователь** — запускайте сервис от непривилегированного пользователя
5. **Логи** — не логируйте PSK и содержимое payload в продакшене

---

## Устранение Неполадок

| Проблема | Решение |
|----------|---------|
| `ConnectionFailed` | Проверьте firewall и доступность UDP-порта |
| `HandshakeFailed` | Убедитесь что PSK совпадает на клиенте и сервере |
| `Timeout` | Увеличьте `--idle-timeout` или проверьте сеть |
| QUIC не работает | UDP может быть заблокирован; используйте HTTP/2 fallback |
| Сборка не компилируется | Проверьте версию Rust: `rustc --version` (≥ 1.70) |
