#!/bin/bash
# =============================================================================
# Phase 8 — Полный деплой с клиента
# =============================================================================
# Этот скрипт:
# 1. Обновляет и пересобирает VPN на СЕРВЕРЕ (по SSH)
# 2. Запускает VPN-сервер на СЕРВЕРЕ (по SSH)
# 3. Обновляет и пересобирает VPN на КЛИЕНТЕ
# 4. Запускает VPN-клиент с DNS-защитой, keepalive, reconnect
#
# Запуск: sudo bash scripts/deploy-phase8.sh
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Настройки (поменяй под себя)
# ---------------------------------------------------------------------------
SERVER_IP="77.110.97.128"
SERVER_USER="root"
SERVER_SSH="${SERVER_USER}@${SERVER_IP}"
REPO_DIR="chameleon-research/rust-core"
PSK="change-me-in-production"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# Проверки
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    err "Запусти от root: sudo bash $0"
fi

info "Phase 8 — деплой VPN с DNS-защитой, keepalive, reconnect"
echo ""

# ---------------------------------------------------------------------------
# Шаг 1: Обновить и пересобрать на СЕРВЕРЕ
# ---------------------------------------------------------------------------
info "=== ШАГ 1: Сборка на сервере ==="

ssh -o ConnectTimeout=10 ${SERVER_SSH} bash -s <<'SERVER_SCRIPT'
set -e
cd ~/chameleon-research

echo "[server] git stash + pull..."
git stash 2>/dev/null || true
git pull origin main
git stash pop 2>/dev/null || true

echo "[server] cargo build --release..."
cd rust-core
cargo build --release --example vpn-server 2>&1 | tail -3

# Остановить старый VPN если запущен
pkill -f "vpn-server" 2>/dev/null && echo "[server] Старый VPN-сервер остановлен" || true
sleep 1

echo "[server] Сборка завершена"
SERVER_SCRIPT

info "Сервер пересобран"

# ---------------------------------------------------------------------------
# Шаг 2: Запустить VPN-сервер
# ---------------------------------------------------------------------------
info "=== ШАГ 2: Запуск VPN-сервера ==="

# Запускаем сервер в фоне через SSH + nohup
ssh ${SERVER_SSH} bash -s <<'SERVER_START'
set -e
cd ~/chameleon-research/rust-core

# Убедиться что старый не запущен
pkill -f "vpn-server" 2>/dev/null || true
sleep 1

# Запустить VPN-сервер в фоне
nohup ./target/release/examples/vpn-server --config configs/vpn-server.toml \
    > /tmp/vpn-server.log 2>&1 &
disown

sleep 2

# Проверить что запустился
if pgrep -f "vpn-server" > /dev/null; then
    echo "[server] VPN-сервер запущен (PID: $(pgrep -f vpn-server))"
    # Показать fingerprint сертификата
    grep -o 'fingerprint=.*' /tmp/vpn-server.log 2>/dev/null | head -1 || true
    grep -o 'Certificate.*' /tmp/vpn-server.log 2>/dev/null | head -1 || true
else
    echo "[server] ОШИБКА: VPN-сервер не запустился!"
    tail -20 /tmp/vpn-server.log
    exit 1
fi
SERVER_START

info "VPN-сервер запущен"

# ---------------------------------------------------------------------------
# Шаг 3: Обновить и пересобрать на КЛИЕНТЕ
# ---------------------------------------------------------------------------
info "=== ШАГ 3: Сборка на клиенте ==="

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${SCRIPT_DIR}"

echo "[client] git stash + pull..."
git stash 2>/dev/null || true
git pull origin main
git stash pop 2>/dev/null || true

echo "[client] cargo build --release..."
cargo build --release --example vpn-client 2>&1 | tail -3

info "Клиент пересобран"

# ---------------------------------------------------------------------------
# Шаг 4: Очистка от старого VPN
# ---------------------------------------------------------------------------
info "=== ШАГ 4: Очистка ==="

# Убить старый VPN-клиент
pkill -f "vpn-client" 2>/dev/null && warn "Старый VPN-клиент остановлен" || true
sleep 1

# Удалить старые маршруты (если зависли)
ip route del ${SERVER_IP}/32 2>/dev/null || true
# Восстановить default route если пропал
DEFAULT_GW=$(ip route show default 2>/dev/null | awk '/via/{print $3; exit}')
if [ -z "$DEFAULT_GW" ]; then
    warn "Default route отсутствует, восстанавливаю..."
    POSSIBLE_GW=$(ip route show | awk '/proto kernel/{print $1}' | head -1)
    if [ -n "$POSSIBLE_GW" ]; then
        # Пытаемся получить шлюз из DHCP
        GW=$(dhclient -v 2>&1 | grep -oP 'routers \K[\d.]+' || echo "")
        if [ -n "$GW" ]; then
            ip route add default via "$GW"
            info "Восстановлен default route через $GW"
        fi
    fi
fi

# Убрать DNS iptables правила если остались
iptables -D OUTPUT -p udp --dport 53 ! -o tun0 -j DROP 2>/dev/null || true
iptables -D OUTPUT -p tcp --dport 53 ! -o tun0 -j DROP 2>/dev/null || true
iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT --to-destination 8.8.8.8:53 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp --dport 53 -j DNAT --to-destination 8.8.8.8:53 2>/dev/null || true

info "Очистка завершена"

# ---------------------------------------------------------------------------
# Шаг 5: Запуск VPN-клиента
# ---------------------------------------------------------------------------
info "=== ШАГ 5: Запуск VPN-клиента ==="
echo ""
echo "  Функции Phase 8:"
echo "    ✓ DNS leak protection (все DNS-запросы через туннель)"
echo "    ✓ Keep-alive (пинг каждые 25 сек)"
echo "    ✓ Auto-reconnect (экспоненциальный backoff)"
echo "    ✓ Cert pinning (готово, нужно указать cert_pin в конфиге)"
echo ""
info "Запускаю VPN-клиент... (Ctrl+C для выхода)"
echo ""

RUST_LOG=info ./target/release/examples/vpn-client --config configs/vpn-client.toml
