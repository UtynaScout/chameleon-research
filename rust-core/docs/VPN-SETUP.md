# VPN Setup Guide

NetSynth VPN creates an encrypted tunnel between two Linux machines using
QUIC transport and ChaCha20-Poly1305 encryption over a TUN device.

## Prerequisites

| Requirement | Details |
|---|---|
| OS | Linux (kernel ≥ 3.x with TUN support) |
| Privileges | `root` or `CAP_NET_ADMIN` capability |
| Packages | `iproute2`, `iptables` |
| Rust | 1.75+ (for build) |

Verify TUN support:
```bash
ls -la /dev/net/tun     # should exist
modprobe tun            # load module if needed
```

## Architecture

```
Client Machine                          Server Machine
┌──────────────┐    QUIC/UDP    ┌──────────────────┐
│  tun0         │◄─────────────►│  tun0              │
│  10.8.0.2/24  │  encrypted    │  10.8.0.1/24       │
│               │  tunnel       │                    │
│  App traffic  │               │  NAT masquerade    │
│  ──► tun0     │               │  tun0 ──► eth0     │
│  ──► QUIC     │               │  ──► internet      │
└──────────────┘               └──────────────────┘
```

- All client traffic is routed through `tun0`
- Client encrypts IP packets → sends over QUIC to server
- Server decrypts → writes to its `tun0` → kernel forwards via NAT
- Return traffic follows the reverse path

## Quick Start

### 1. Build

```bash
cd rust-core
cargo build --release --example vpn-server --example vpn-client
```

### 2. Server Setup

On the **server machine** (public-facing):

```bash
# Edit config
cp configs/vpn-server.toml /etc/vpn-server.toml
vi /etc/vpn-server.toml     # set psk, external_iface

# Run (requires root)
sudo RUST_LOG=info ./target/release/examples/vpn-server \
    --config /etc/vpn-server.toml
```

Or with CLI args:
```bash
sudo RUST_LOG=info ./target/release/examples/vpn-server \
    --port 4433 \
    --psk "my-secret-key" \
    --tun-addr 10.8.0.1 \
    --tun-name tun0 \
    --external-iface eth0
```

The server will:
1. Create `tun0` with IP `10.8.0.1/24`
2. Enable IPv4 forwarding (`/proc/sys/net/ipv4/ip_forward`)
3. Add iptables MASQUERADE on the external interface
4. Listen for QUIC connections on the specified UDP port

### 3. Client Setup

On the **client machine**:

```bash
# Edit config
cp configs/vpn-client.toml /etc/vpn-client.toml
vi /etc/vpn-client.toml     # set server IP, psk, tun_addr

# Run (requires root)
sudo RUST_LOG=info ./target/release/examples/vpn-client \
    --config /etc/vpn-client.toml
```

Or with CLI args:
```bash
sudo RUST_LOG=info ./target/release/examples/vpn-client \
    --server 203.0.113.10:4433 \
    --psk "my-secret-key" \
    --tun-addr 10.8.0.2 \
    --tun-name tun0
```

The client will:
1. Save the current default gateway
2. Create `tun0` with IP `10.8.0.2/24`
3. Connect to the server via QUIC
4. Add a host route for the server IP via the original gateway
5. Redirect the default route through `tun0`
6. Relay packets: TUN ↔ encrypted QUIC tunnel

On Ctrl+C the client restores the original routing table.

### 4. Verify

```bash
# On the client, check your public IP goes through the server
curl ifconfig.me

# Ping the server's TUN address
ping 10.8.0.1

# Trace the route
traceroute 8.8.8.8
```

## Multiple Clients

Each client must use a unique TUN address:

| Client | `tun_addr` |
|---|---|
| Client 1 | `10.8.0.2` |
| Client 2 | `10.8.0.3` |
| Client 3 | `10.8.0.4` |
| ... | up to `10.8.0.254` |

The server auto-learns client IPs from the first packet's IPv4 source
header. No explicit IP assignment protocol is needed.

## Docker Deployment

### Server

```bash
cd rust-core

# Edit config
vi configs/vpn-server.toml

# Build and run
docker compose -f docker/docker-compose.yml up vpn-server -d
```

### Client

```bash
# Edit config with server's public IP
vi configs/vpn-client.toml

docker compose -f docker/docker-compose.yml up vpn-client
```

Both containers require:
- `NET_ADMIN` capability (for TUN/route management)
- `/dev/net/tun` device access

## Configuration Reference

### Server (`configs/vpn-server.toml`)

| Field | Default | Description |
|---|---|---|
| `port` | `4433` | UDP listen port |
| `psk` | `"vpn-psk"` | Pre-shared key for HKDF key derivation |
| `tun_addr` | `"10.8.0.1"` | Server TUN IP |
| `tun_name` | `"tun0"` | TUN device name |
| `external_iface` | `"eth0"` | Interface for NAT masquerade |

### Client (`configs/vpn-client.toml`)

| Field | Default | Description |
|---|---|---|
| `server` | `"127.0.0.1:4433"` | Server address (IP:port) |
| `psk` | `"vpn-psk"` | Pre-shared key (must match server) |
| `tun_addr` | `"10.8.0.2"` | Client TUN IP |
| `tun_name` | `"tun0"` | TUN device name |

## Security Notes

- The QUIC TLS layer uses **self-signed certificates** with an insecure
  verifier (no CA validation). This is acceptable for lab/testing
  environments. For production, use proper PKI certificates.
- Traffic is encrypted with **ChaCha20-Poly1305** (AEAD) using
  counter-based nonces derived per-direction.
- The PSK is used as input to **HKDF-SHA256** to derive the tunnel
  encryption key — choose a strong, random PSK in production.
- **DNS is not automatically redirected.** Configure your DNS resolver
  to use an address that routes through the tunnel (e.g., `8.8.8.8`)
  or set up a DNS server on the VPN subnet.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `open /dev/net/tun: No such file` | TUN module not loaded | `sudo modprobe tun` |
| `ioctl TUNSETIFF: Operation not permitted` | Not root | Run with `sudo` |
| QUIC connection timeout | Firewall blocking UDP port | Open `4433/udp` on server |
| No internet after connecting | NAT not working | Check `external_iface` matches real interface |
| DNS not resolving | DNS still using old route | Set DNS to `8.8.8.8` manually |
| Routes not restored after crash | Client didn't clean up | `sudo ip route del default; sudo ip route add default via <gateway>` |
