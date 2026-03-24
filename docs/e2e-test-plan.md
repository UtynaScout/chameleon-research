# End-to-End Test Plan — Phase 2.3

## Overview

Validates the full Chameleon pipeline: **Weaver → Frame → Crypto → Transport → Network → Decrypt → Verify**.

## Test Matrix

### Localhost Tests

| # | Test | Status | Assertion |
|---|------|--------|-----------|
| 1 | Server starts on `0.0.0.0:4433` | ⬜ | No panic, endpoint bound |
| 2 | Client connects via QUIC | ⬜ | Handshake completes |
| 3 | Encrypted frame roundtrip | ⬜ | Decrypted == original |
| 4 | D_KL size distribution check | ⬜ | Entropy > 0.5 bits |
| 5 | 20 concurrent connections | ⬜ | All echoes match |
| 6 | HTTP/2 fallback roundtrip | ⬜ | Echoed == sent |
| 7 | 10 streams on one connection | ⬜ | All echoes match |

### Real Network Tests (Manual)

| # | Test | Status | Notes |
|---|------|--------|-------|
| 1 | Two machines on LAN | ⬜ | Replace `localhost` with LAN IP |
| 2 | Through NAT | ⬜ | Requires port forwarding |
| 3 | Through firewall (HTTP/2) | ⬜ | TCP/443 fallback path |

### Stress Tests (Manual)

| # | Test | Status | Target |
|---|------|--------|--------|
| 1 | 100 concurrent clients | ⬜ | All echoes within 5 s |
| 2 | 1000+ packets/s sustained | ⬜ | No packet loss over 10 s |
| 3 | Long-running (10 min) | ⬜ | No memory leak, stable RTT |

## Running Tests

```powershell
# Automated E2E tests (localhost)
cd rust-core
cargo test --test e2e_tests

# Interactive: start server, then client
cargo run --example server -- --port 4433
cargo run --example client -- --server 127.0.0.1:4433 --duration 10
```

## Architecture

```
┌──────────┐    ┌───────┐    ┌────────┐    ┌───────────┐
│  Weaver  │───▶│ Frame │───▶│ Crypto │───▶│ Transport │
│ (Markov) │    │(encode)│   │(encrypt)│   │  (QUIC)   │
└──────────┘    └───────┘    └────────┘    └─────┬─────┘
                                                 │ network
                                           ┌─────▼─────┐
                                           │ Transport  │
                                           │  (recv)    │
                                           └─────┬─────┘
                                           ┌─────▼─────┐    ┌───────┐
                                           │  Crypto   │───▶│ Frame │
                                           │ (decrypt) │    │(decode)│
                                           └───────────┘    └───────┘
```

## Success Criteria

- `cargo test --test e2e_tests` — all tests passing
- `cargo build --release` — zero warnings
- Interactive demo works: server + client on localhost
- Session stats printed by client example
