//! NetSynth VPN client — route all traffic through an encrypted QUIC tunnel.
//!
//! Creates a TUN device, connects to the VPN server, redirects the default
//! route through the tunnel, and relays IP packets bidirectionally.
//!
//! ```bash
//! sudo cargo run --example vpn-client -- --server 192.168.1.100:4433 --tun-addr 10.8.0.2
//! # or with config file:
//! sudo cargo run --example vpn-client -- --config configs/vpn-client.toml
//! ```

use std::net::{Ipv4Addr, SocketAddr};

use chameleon_core::crypto::derive_session_key;
use chameleon_core::transport::quic::QuicTransport;
use chameleon_core::transport::TransportConfig;
use chameleon_core::tun::route::RouteManager;
use chameleon_core::tun::{TunDevice, VpnTunnel};
use clap::Parser;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// CLI / config
// ---------------------------------------------------------------------------

/// NetSynth VPN client.
#[derive(Parser)]
#[command(name = "netsynth-vpn-client")]
struct Args {
    /// Path to TOML config file (overrides CLI defaults).
    #[arg(short, long)]
    config: Option<String>,

    /// VPN server address (host:port).
    #[arg(short, long, default_value = "127.0.0.1:4433")]
    server: String,

    /// Pre-shared key (must match server).
    #[arg(long, default_value = "vpn-psk")]
    psk: String,

    /// Client TUN address in the VPN subnet.
    #[arg(long, default_value = "10.8.0.2")]
    tun_addr: String,

    /// TUN device name.
    #[arg(long, default_value = "tun0")]
    tun_name: String,
}

#[derive(serde::Deserialize, Default)]
struct FileConfig {
    server: Option<String>,
    psk: Option<String>,
    tun_addr: Option<String>,
    tun_name: Option<String>,
}

struct Settings {
    server: String,
    psk: String,
    tun_addr: String,
    tun_name: String,
}

impl Settings {
    fn from_args(args: Args) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(path) = &args.config {
            let content = std::fs::read_to_string(path)?;
            let fc: FileConfig = toml::from_str(&content)?;
            Ok(Self {
                server: fc.server.unwrap_or(args.server),
                psk: fc.psk.unwrap_or(args.psk),
                tun_addr: fc.tun_addr.unwrap_or(args.tun_addr),
                tun_name: fc.tun_name.unwrap_or(args.tun_name),
            })
        } else {
            Ok(Self {
                server: args.server,
                psk: args.psk,
                tun_addr: args.tun_addr,
                tun_name: args.tun_name,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let settings = Settings::from_args(Args::parse())?;

    let key = derive_session_key(settings.psk.as_bytes(), b"vpn-salt", b"vpn-tunnel");
    let server_addr: SocketAddr = settings.server.parse()?;
    let server_ip = server_addr.ip().to_string();
    let tun_addr: Ipv4Addr = settings.tun_addr.parse()?;

    // ---- Save current gateway before we change routes ----
    let saved_gw = RouteManager::get_default_gateway()?;
    info!(gateway = %saved_gw, "Saved default gateway");

    // ---- TUN device ----
    let tun = TunDevice::new(
        &settings.tun_name,
        tun_addr,
        Ipv4Addr::new(255, 255, 255, 0),
    )?;
    info!(dev = tun.name(), addr = %tun_addr, "TUN device ready");

    // ---- QUIC connection ----
    let mut transport = QuicTransport::new(TransportConfig::default());
    transport.bind_client().await?;
    transport.connect(server_addr, "localhost").await?;
    let conn = transport
        .connection()
        .expect("connected")
        .clone();
    info!(server = %server_addr, "Connected to VPN server");

    // ---- Route management ----
    // Ensure QUIC traffic reaches the server directly (not via TUN loop)
    RouteManager::add_server_route(&server_ip, &saved_gw)?;
    // Redirect all other traffic through TUN
    RouteManager::set_default_route(tun.name())?;
    info!("Default route set through {}", tun.name());

    // ---- VPN tunnel ----
    let tunnel = VpnTunnel::client(&conn, key).await?;
    let (mut tunnel_tx, mut tunnel_rx) = tunnel.split();

    let tun_r = tun.clone();
    let tun_w = tun.clone();

    // TUN → Tunnel: capture local traffic, encrypt, send to server
    let t1 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun_r.read(&mut buf).await {
                Ok(n) => {
                    if tunnel_tx.send_packet(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("TUN read: {e}");
                    break;
                }
            }
        }
    });

    // Tunnel → TUN: receive from server, decrypt, inject into local stack
    let t2 = tokio::spawn(async move {
        loop {
            match tunnel_rx.recv_packet().await {
                Ok(pkt) => {
                    if let Err(e) = tun_w.write(&pkt).await {
                        warn!("TUN write: {e}");
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

    // Wait for shutdown or relay failure
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    tokio::select! {
        _ = t1 => { info!("TUN→Tunnel relay ended"); }
        _ = t2 => { info!("Tunnel→TUN relay ended"); }
        _ = &mut shutdown => { info!("Ctrl+C received"); }
    }

    // ---- Restore routes ----
    let _ = RouteManager::remove_server_route(&server_ip);
    let _ = RouteManager::restore_default_route(&saved_gw);
    info!(gateway = %saved_gw, "Routes restored");

    conn.close(0u32.into(), b"shutdown");

    Ok(())
}
