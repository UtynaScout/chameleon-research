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
use std::time::Duration;

use chameleon_core::crypto::derive_session_key;
use chameleon_core::transport::dpi::{DpiProfile, FingerprintPreset, PaddingConfig, PaddingMode, ShapingProfile};
use chameleon_core::transport::quic::QuicTransport;
use chameleon_core::transport::reconnect::ReconnectConfig;
use chameleon_core::transport::shaper::TrafficShaper;
use chameleon_core::transport::TransportConfig;
use chameleon_core::tun::dns::{DnsInterceptor, DEFAULT_DNS_SERVERS};
use chameleon_core::tun::keepalive;
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

    /// TLS server name for QUIC handshake (must match server cert SAN).
    /// Defaults to the server IP address.
    #[arg(long)]
    server_name: Option<String>,

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
    server_name: Option<String>,
    psk: Option<String>,
    tun_addr: Option<String>,
    tun_name: Option<String>,
    // DPI resistance fields
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    tls_fingerprint: Option<String>,
    // Padding
    padding: Option<PaddingFileConfig>,
    // Traffic shaping
    shaping: Option<String>,
    // Phase 8: DNS
    dns: Option<DnsFileConfig>,
    // Phase 8: Keep-alive
    keepalive: Option<KeepaliveFileConfig>,
    // Phase 8: Reconnect
    reconnect: Option<ReconnectFileConfig>,
    // Phase 8: Certificate pinning
    cert_pin: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct DnsFileConfig {
    enabled: Option<bool>,
    servers: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Default)]
struct KeepaliveFileConfig {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
}

#[derive(serde::Deserialize, Default)]
struct ReconnectFileConfig {
    enabled: Option<bool>,
    max_retries: Option<u32>,
    max_delay_secs: Option<u64>,
}

#[derive(serde::Deserialize, Default)]
struct PaddingFileConfig {
    enabled: Option<bool>,
    mode: Option<String>,
    mss_values: Option<Vec<usize>>,
    fixed_size: Option<usize>,
    min_size: Option<usize>,
    max_size: Option<usize>,
}

struct Settings {
    server: String,
    server_name: Option<String>,
    psk: String,
    tun_addr: String,
    tun_name: String,
    dpi: DpiProfile,
    dns_enabled: bool,
    dns_servers: Vec<String>,
    keepalive_enabled: bool,
    keepalive_interval_secs: u64,
    reconnect_enabled: bool,
    reconnect_config: ReconnectConfig,
    #[allow(dead_code)] // will be used when QUIC bind supports cert pinning
    cert_pin: Option<String>,
}

impl Settings {
    fn from_args(args: Args) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(path) = &args.config {
            let content = std::fs::read_to_string(path)?;
            let fc: FileConfig = toml::from_str(&content)?;

            // Build DPI profile from TOML fields
            let dpi = Self::build_dpi_profile(&fc);

            // DNS config
            let dns_enabled = fc.dns.as_ref().and_then(|d| d.enabled).unwrap_or(true);
            let dns_servers = fc
                .dns
                .as_ref()
                .and_then(|d| d.servers.clone())
                .unwrap_or_else(|| DEFAULT_DNS_SERVERS.iter().map(|s| s.to_string()).collect());

            // Keep-alive config
            let keepalive_enabled = fc.keepalive.as_ref().and_then(|k| k.enabled).unwrap_or(true);
            let keepalive_interval_secs = fc
                .keepalive
                .as_ref()
                .and_then(|k| k.interval_secs)
                .unwrap_or(keepalive::DEFAULT_KEEPALIVE_INTERVAL_SECS);

            // Reconnect config
            let reconnect_enabled = fc.reconnect.as_ref().and_then(|r| r.enabled).unwrap_or(true);
            let reconnect_config = ReconnectConfig {
                max_retries: fc.reconnect.as_ref().and_then(|r| r.max_retries).unwrap_or(0),
                max_delay: Duration::from_secs(
                    fc.reconnect.as_ref().and_then(|r| r.max_delay_secs).unwrap_or(30),
                ),
                ..Default::default()
            };

            Ok(Self {
                server: fc.server.unwrap_or(args.server),
                server_name: fc.server_name.or(args.server_name),
                psk: fc.psk.unwrap_or(args.psk),
                tun_addr: fc.tun_addr.unwrap_or(args.tun_addr),
                tun_name: fc.tun_name.unwrap_or(args.tun_name),
                dpi,
                dns_enabled,
                dns_servers,
                keepalive_enabled,
                keepalive_interval_secs,
                reconnect_enabled,
                reconnect_config,
                cert_pin: fc.cert_pin,
            })
        } else {
            Ok(Self {
                server: args.server,
                server_name: args.server_name,
                psk: args.psk,
                tun_addr: args.tun_addr,
                tun_name: args.tun_name,
                dpi: DpiProfile::default(),
                dns_enabled: true,
                dns_servers: DEFAULT_DNS_SERVERS.iter().map(|s| s.to_string()).collect(),
                keepalive_enabled: true,
                keepalive_interval_secs: keepalive::DEFAULT_KEEPALIVE_INTERVAL_SECS,
                reconnect_enabled: true,
                reconnect_config: ReconnectConfig::default(),
                cert_pin: None,
            })
        }
    }

    fn build_dpi_profile(fc: &FileConfig) -> DpiProfile {
        let sni = fc.tls_sni.clone();
        let alpn = fc
            .tls_alpn
            .as_deref()
            .map(|a| vec![a.to_string()])
            .unwrap_or_else(|| vec!["h3".into()]);
        let fingerprint = fc
            .tls_fingerprint
            .as_deref()
            .and_then(|s| FingerprintPreset::from_str(s).ok())
            .unwrap_or(FingerprintPreset::RustlsDefault);

        let padding = if let Some(ref pcfg) = fc.padding {
            let mode = match pcfg.mode.as_deref() {
                Some("mss") => {
                    PaddingMode::Mss(pcfg.mss_values.clone().unwrap_or_else(|| vec![1200, 1350, 1500]))
                }
                Some("fixed") => PaddingMode::Fixed(pcfg.fixed_size.unwrap_or(1200)),
                Some("random") => PaddingMode::Random {
                    min_size: pcfg.min_size.unwrap_or(256),
                    max_size: pcfg.max_size.unwrap_or(1350),
                },
                _ => PaddingMode::None,
            };
            PaddingConfig {
                enabled: pcfg.enabled.unwrap_or(false),
                mode,
            }
        } else {
            PaddingConfig::default()
        };

        let shaping = fc
            .shaping
            .as_deref()
            .and_then(|s| ShapingProfile::from_str(s).ok())
            .unwrap_or(ShapingProfile::None);

        DpiProfile {
            sni,
            alpn,
            fingerprint,
            padding,
            shaping,
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

    // ---- QUIC connection (with optional reconnect) ----
    let connect_name = settings.dpi.sni.clone().unwrap_or_else(|| {
        settings
            .server_name
            .clone()
            .unwrap_or_else(|| server_addr.ip().to_string())
    });

    let transport = if settings.reconnect_enabled {
        chameleon_core::transport::reconnect::connect_with_retry(
            server_addr,
            &connect_name,
            &settings.dpi,
            &settings.reconnect_config,
        )
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?
    } else {
        let mut t = QuicTransport::new(TransportConfig::default());
        if settings.dpi.fingerprint != FingerprintPreset::RustlsDefault
            || settings.dpi.alpn != vec!["h3".to_string()]
            || settings.dpi.sni.is_some()
        {
            t.bind_client_with_dpi(&settings.dpi).await?;
            info!(
                fingerprint = settings.dpi.fingerprint.description(),
                alpn = ?settings.dpi.alpn,
                "DPI profile applied"
            );
        } else {
            t.bind_client().await?;
        }
        t.connect(server_addr, &connect_name).await?;
        t
    };

    let conn = transport
        .connection()
        .expect("connected")
        .clone();
    info!(server = %server_addr, "Connected to VPN server");

    // ---- Route management ----
    RouteManager::add_server_route(&server_ip, &saved_gw)?;
    RouteManager::set_default_route(tun.name())?;
    info!("Default route set through {}", tun.name());

    // ---- DNS interception (Phase 8) ----
    let mut dns_interceptor = DnsInterceptor::new(tun.name(), &settings.tun_addr);
    if settings.dns_enabled {
        let dns_refs: Vec<&str> = settings.dns_servers.iter().map(|s| s.as_str()).collect();
        dns_interceptor.install(&dns_refs)?;
        info!(servers = ?settings.dns_servers, "DNS interception enabled");
    }

    // ---- VPN tunnel ----
    let mut tunnel = VpnTunnel::client(&conn, key).await?;

    if settings.dpi.padding.enabled {
        tunnel.set_padding(settings.dpi.padding.clone());
        info!(mode = ?settings.dpi.padding.mode, "Packet padding enabled");
    }

    let (tunnel_tx, mut tunnel_rx) = tunnel.split();

    let tun_r = tun.clone();
    let tun_w = tun.clone();

    let shaping = settings.dpi.shaping.clone();
    let use_shaper = shaping != ShapingProfile::None;

    // ---- Keep-alive (Phase 8) ----
    let _keepalive_handle = if settings.keepalive_enabled {
        let interval = Duration::from_secs(settings.keepalive_interval_secs);
        let (handle, _rx) = keepalive::spawn_keepalive(interval);
        info!(interval_secs = settings.keepalive_interval_secs, "Keep-alive enabled");
        Some(handle)
    } else {
        None
    };

    // TUN → Tunnel: capture local IPv4 traffic, encrypt, send to server
    let t1 = if use_shaper {
        let shaper = TrafficShaper::new(tunnel_tx, &shaping, settings.dpi.padding.clone());
        info!(profile = ?shaping, "Traffic shaping enabled");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match tun_r.read(&mut buf).await {
                    Ok(n) if n >= 20 && (buf[0] >> 4) == 4 => {
                        if shaper.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("TUN read: {e}");
                        break;
                    }
                }
            }
        })
    } else {
        let mut tunnel_tx = tunnel_tx;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match tun_r.read(&mut buf).await {
                    Ok(n) if n >= 20 && (buf[0] >> 4) == 4 => {
                        if tunnel_tx.send_packet(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("TUN read: {e}");
                        break;
                    }
                }
            }
        })
    };

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

    // ---- Cleanup ----
    // DNS interception is restored automatically via Drop,
    // but explicit uninstall provides better error reporting
    if settings.dns_enabled {
        let _ = dns_interceptor.uninstall();
        info!("DNS interception removed");
    }

    let _ = RouteManager::remove_server_route(&server_ip);
    let _ = RouteManager::restore_default_route(&saved_gw);
    info!(gateway = %saved_gw, "Routes restored");

    conn.close(0u32.into(), b"shutdown");

    Ok(())
}
