//! NetSynth VPN server — multi-client QUIC tunnel with TUN forwarding.
//!
//! Accepts encrypted VPN connections over QUIC, forwards client traffic to
//! the internet via a TUN device with NAT masquerade.
//!
//! ```bash
//! sudo cargo run --example vpn-server -- --port 4433 --tun-addr 10.8.0.1
//! # or with config file:
//! sudo cargo run --example vpn-server -- --config configs/vpn-server.toml
//! ```

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use chameleon_core::crypto::derive_session_key;
use chameleon_core::transport::quic::QuicTransport;
use chameleon_core::tun::route::RouteManager;
use chameleon_core::tun::{TunDevice, VpnTunnel};
use clap::Parser;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// CLI / config
// ---------------------------------------------------------------------------

/// NetSynth VPN server.
#[derive(Parser)]
#[command(name = "netsynth-vpn-server")]
struct Args {
    /// Path to TOML config file (overrides CLI defaults).
    #[arg(short, long)]
    config: Option<String>,

    /// UDP port to listen on.
    #[arg(short, long, default_value_t = 4433)]
    port: u16,

    /// Pre-shared key (must match clients).
    #[arg(long, default_value = "vpn-psk")]
    psk: String,

    /// Server TUN address in the VPN subnet.
    #[arg(long, default_value = "10.8.0.1")]
    tun_addr: String,

    /// TUN device name.
    #[arg(long, default_value = "tun0")]
    tun_name: String,

    /// External network interface for NAT masquerade.
    #[arg(long, default_value = "eth0")]
    external_iface: String,

    /// Additional TLS certificate SANs (IP addresses or hostnames).
    /// The server's public IP should be listed here so clients can connect by IP.
    /// "localhost" and "127.0.0.1" are always included.
    #[arg(long)]
    san: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct FileConfig {
    port: Option<u16>,
    psk: Option<String>,
    tun_addr: Option<String>,
    tun_name: Option<String>,
    external_iface: Option<String>,
    san: Option<Vec<String>>,
}

struct Settings {
    port: u16,
    psk: String,
    tun_addr: String,
    tun_name: String,
    external_iface: String,
    san: Vec<String>,
}

impl Settings {
    fn from_args(args: Args) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(path) = &args.config {
            let content = std::fs::read_to_string(path)?;
            let fc: FileConfig = toml::from_str(&content)?;
            Ok(Self {
                port: fc.port.unwrap_or(args.port),
                psk: fc.psk.unwrap_or(args.psk),
                tun_addr: fc.tun_addr.unwrap_or(args.tun_addr),
                tun_name: fc.tun_name.unwrap_or(args.tun_name),
                external_iface: fc.external_iface.unwrap_or(args.external_iface),
                san: fc.san.unwrap_or(args.san),
            })
        } else {
            Ok(Self {
                port: args.port,
                psk: args.psk,
                tun_addr: args.tun_addr,
                tun_name: args.tun_name,
                external_iface: args.external_iface,
                san: args.san,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Per-client channel keyed by the client's TUN IP.
type ClientRoutes = Arc<RwLock<HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>>>;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let settings = Settings::from_args(Args::parse())?;

    let key = derive_session_key(settings.psk.as_bytes(), b"vpn-salt", b"vpn-tunnel");
    let addr: SocketAddr = format!("0.0.0.0:{}", settings.port).parse()?;

    // ---- TUN device + routing ----
    let tun_addr: Ipv4Addr = settings.tun_addr.parse()?;
    let tun = TunDevice::new(&settings.tun_name, tun_addr, Ipv4Addr::new(255, 255, 255, 0))?;
    info!(dev = tun.name(), addr = %tun_addr, "TUN device ready");

    RouteManager::enable_ip_forwarding()?;
    RouteManager::add_nat_rule(&settings.external_iface)?;
    info!(iface = %settings.external_iface, "IP forwarding + NAT enabled");

    // ---- Shared channels ----
    let routes: ClientRoutes = Arc::new(RwLock::new(HashMap::new()));
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(512);

    // Background: write packets from all clients to TUN
    let tun_w = tun.clone();
    tokio::spawn(async move {
        while let Some(pkt) = to_tun_rx.recv().await {
            if let Err(e) = tun_w.write(&pkt).await {
                warn!("TUN write: {e}");
            }
        }
    });

    // Background: read TUN and dispatch to per-client channels by IPv4 dst
    let tun_r = tun.clone();
    let routes_reader = Arc::clone(&routes);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun_r.read(&mut buf).await {
                Ok(n) if n >= 20 => {
                    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
                    let map = routes_reader.read().await;
                    if let Some(tx) = map.get(&dst) {
                        let _ = tx.try_send(buf[..n].to_vec());
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("TUN read: {e}");
                    break;
                }
            }
        }
    });

    // ---- QUIC server ----
    // Build cert SANs: always include localhost + 127.0.0.1, plus any extras
    let mut san_list: Vec<String> = vec!["localhost".into(), "127.0.0.1".into()];
    for s in &settings.san {
        if !san_list.contains(s) {
            san_list.push(s.clone());
        }
    }
    let san_refs: Vec<&str> = san_list.iter().map(|s| s.as_str()).collect();
    let (endpoint, _cert) = QuicTransport::bind_server_with_san(addr, &san_refs).await?;
    info!(addr = %endpoint.local_addr()?, san = ?san_list, "VPN server listening");

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let key = key;
                let routes = Arc::clone(&routes);
                let to_tun = to_tun_tx.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            let remote = conn.remote_address();
                            info!(%remote, "Client connected");
                            if let Err(e) = handle_client(conn, key, routes, to_tun).await {
                                warn!(%remote, "Session ended: {e}");
                            }
                        }
                        Err(e) => warn!("Accept error: {e}"),
                    }
                });
            }
            _ = &mut shutdown => {
                info!("Shutting down — cleaning NAT rules");
                let _ = RouteManager::remove_nat_rule(&settings.external_iface);
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-client handler
// ---------------------------------------------------------------------------

async fn handle_client(
    conn: quinn::Connection,
    key: [u8; 32],
    routes: ClientRoutes,
    to_tun: mpsc::Sender<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tunnel = VpnTunnel::server(&conn, key).await?;
    let (mut tunnel_tx, mut tunnel_rx) = tunnel.split();

    let (client_tx, mut client_rx) = mpsc::channel::<Vec<u8>>(512);

    // Track auto-learned IPs for cleanup
    let learned: Arc<RwLock<Vec<Ipv4Addr>>> = Arc::new(RwLock::new(Vec::new()));

    // Tunnel → TUN: decrypt client packets, auto-learn IP, forward to TUN
    let routes_learn = Arc::clone(&routes);
    let client_tx_learn = client_tx.clone();
    let learned_t1 = Arc::clone(&learned);
    let t1 = tokio::spawn(async move {
        loop {
            match tunnel_rx.recv_packet().await {
                Ok(pkt) => {
                    if pkt.len() >= 20 {
                        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                        let mut map = routes_learn.write().await;
                        if !map.contains_key(&src) {
                            info!(%src, "Learned client IP");
                            map.insert(src, client_tx_learn.clone());
                            learned_t1.write().await.push(src);
                        }
                    }
                    if to_tun.send(pkt).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    info!("Tunnel closed: {e}");
                    break;
                }
            }
        }
    });

    // TUN → Tunnel: send response packets back to this client
    let t2 = tokio::spawn(async move {
        while let Some(pkt) = client_rx.recv().await {
            if tunnel_tx.send_packet(&pkt).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }

    // Cleanup learned routes
    let ips = learned.read().await;
    let mut map = routes.write().await;
    for ip in ips.iter() {
        map.remove(ip);
        info!(%ip, "Removed client route");
    }

    Ok(())
}
