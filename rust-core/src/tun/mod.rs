//! TUN device and VPN tunnel support.
//!
//! [`TunDevice`] provides access to a kernel TUN adapter (Linux only).
//! Other platforms receive a stub that returns [`TunError::Unsupported`].
//!
//! [`VpnTunnel`] is a cross-platform encrypted packet transport over
//! a persistent QUIC bidirectional stream using ChaCha20-Poly1305 with
//! counter-based nonces.

pub mod dns;
pub mod keepalive;
pub mod route;

use crate::crypto::cipher;
use crate::transport::dpi::PaddingConfig;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from TUN and VPN tunnel operations.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("device creation failed: {0}")]
    DeviceCreation(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed")]
    Decryption,
    #[error("TUN not supported on this platform")]
    Unsupported,
    #[error("route error: {0}")]
    Route(String),
}

// ---------------------------------------------------------------------------
// TunDevice — Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod device_impl {
    use super::TunError;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;
    use tokio::io::unix::AsyncFd;

    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    /// A Linux TUN network device.
    ///
    /// Wraps a `/dev/net/tun` file descriptor with async I/O via
    /// [`tokio::io::unix::AsyncFd`]. Cloneable (Arc-backed) so the same
    /// device can be read and written from separate tasks.
    #[derive(Clone)]
    pub struct TunDevice {
        fd: Arc<AsyncFd<OwnedFd>>,
        name: String,
    }

    impl TunDevice {
        /// Create and configure a TUN device.
        ///
        /// Requires **root** or **CAP_NET_ADMIN**. Runs `ip addr add` and
        /// `ip link set up` to configure the interface.
        pub fn new(name: &str, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<Self, TunError> {
            // Open /dev/net/tun
            let fd = unsafe {
                libc::open(
                    b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                    libc::O_RDWR | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(TunError::DeviceCreation(format!(
                    "open /dev/net/tun: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Fill ifreq and call TUNSETIFF
            let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    name_bytes.as_ptr(),
                    ifr.ifr_name.as_mut_ptr() as *mut u8,
                    copy_len,
                );
                ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
            }

            if unsafe { libc::ioctl(fd, TUNSETIFF as libc::c_ulong, &ifr) } < 0 {
                unsafe {
                    libc::close(fd);
                }
                return Err(TunError::DeviceCreation(format!(
                    "ioctl TUNSETIFF: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Read back actual device name
            let actual_name = {
                let ptr = ifr.ifr_name.as_ptr() as *const u8;
                let len = unsafe {
                    (0..libc::IFNAMSIZ)
                        .position(|i| *ptr.add(i) == 0)
                        .unwrap_or(libc::IFNAMSIZ)
                };
                unsafe {
                    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).to_string()
                }
            };

            // Configure IP and bring up
            Self::configure(&actual_name, addr, netmask)?;

            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let async_fd =
                AsyncFd::new(owned).map_err(|e| TunError::DeviceCreation(e.to_string()))?;

            Ok(Self {
                fd: Arc::new(async_fd),
                name: actual_name,
            })
        }

        fn configure(name: &str, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<(), TunError> {
            let prefix = u32::from(netmask).count_ones();
            run_cmd("ip", &["addr", "add", &format!("{addr}/{prefix}"), "dev", name])?;
            run_cmd("ip", &["link", "set", name, "up"])?;
            Ok(())
        }

        /// Read a single IP packet from the TUN device.
        pub async fn read(&self, buf: &mut [u8]) -> Result<usize, TunError> {
            loop {
                let mut guard =
                    self.fd.readable().await.map_err(|e| TunError::Io(e.to_string()))?;
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::read(
                            inner.get_ref().as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(result) => return result.map_err(|e| TunError::Io(e.to_string())),
                    Err(_would_block) => continue,
                }
            }
        }

        /// Write an IP packet to the TUN device.
        pub async fn write(&self, buf: &[u8]) -> Result<usize, TunError> {
            loop {
                let mut guard =
                    self.fd.writable().await.map_err(|e| TunError::Io(e.to_string()))?;
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::write(
                            inner.get_ref().as_raw_fd(),
                            buf.as_ptr() as *const libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(result) => return result.map_err(|e| TunError::Io(e.to_string())),
                    Err(_would_block) => continue,
                }
            }
        }

        /// Returns the kernel device name (e.g. `tun0`).
        pub fn name(&self) -> &str {
            &self.name
        }
    }

    fn run_cmd(program: &str, args: &[&str]) -> Result<(), TunError> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| TunError::DeviceCreation(format!("{program}: {e}")))?;
        if !output.status.success() {
            return Err(TunError::DeviceCreation(format!(
                "{program} {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use device_impl::TunDevice;

// ---------------------------------------------------------------------------
// TunDevice — non-Linux stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
#[derive(Clone)]
pub struct TunDevice {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
impl TunDevice {
    pub fn new(
        _name: &str,
        _addr: std::net::Ipv4Addr,
        _netmask: std::net::Ipv4Addr,
    ) -> Result<Self, TunError> {
        Err(TunError::Unsupported)
    }
    pub async fn read(&self, _buf: &mut [u8]) -> Result<usize, TunError> {
        Err(TunError::Unsupported)
    }
    pub async fn write(&self, _buf: &[u8]) -> Result<usize, TunError> {
        Err(TunError::Unsupported)
    }
    pub fn name(&self) -> &str {
        ""
    }
}

// ---------------------------------------------------------------------------
// VpnTunnel — cross-platform encrypted QUIC tunnel
// ---------------------------------------------------------------------------

/// Encrypted bidirectional VPN tunnel over a persistent QUIC bi-stream.
///
/// Each IP packet is encrypted with ChaCha20-Poly1305 using a counter-based
/// nonce scheme and sent as a length-prefixed frame:
///
/// ```text
/// [2 bytes BE: ciphertext length][N bytes: encrypted IP packet]
/// ```
///
/// Nonce layout (12 bytes): `[direction: 4 bytes LE][counter: 8 bytes LE]`
/// ensuring unique nonces per direction.
pub struct VpnTunnel {
    sender: VpnTunnelSender,
    receiver: VpnTunnelReceiver,
}

/// Sending half of a [`VpnTunnel`].
pub struct VpnTunnelSender {
    send: quinn::SendStream,
    key: [u8; 32],
    counter: u64,
    direction: u8,
    padding: Option<PaddingConfig>,
}

/// Receiving half of a [`VpnTunnel`].
pub struct VpnTunnelReceiver {
    recv: quinn::RecvStream,
    key: [u8; 32],
    counter: u64,
    direction: u8,
    padding_enabled: bool,
}

impl VpnTunnel {
    /// Create a tunnel on the **client** side (opens a new bi-stream).
    ///
    /// Direction byte: `0` (client → server).
    pub async fn client(conn: &quinn::Connection, key: [u8; 32]) -> Result<Self, TunError> {
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| TunError::Transport(e.to_string()))?;
        Ok(Self {
            sender: VpnTunnelSender {
                send,
                key,
                counter: 0,
                direction: 0,
                padding: None,
            },
            receiver: VpnTunnelReceiver {
                recv,
                key,
                counter: 0,
                direction: 0,
                padding_enabled: false,
            },
        })
    }

    /// Create a tunnel on the **server** side (accepts an incoming bi-stream).
    ///
    /// Direction byte: `1` (server → client).
    pub async fn server(conn: &quinn::Connection, key: [u8; 32]) -> Result<Self, TunError> {
        let (send, recv) = conn
            .accept_bi()
            .await
            .map_err(|e| TunError::Transport(e.to_string()))?;
        Ok(Self {
            sender: VpnTunnelSender {
                send,
                key,
                counter: 0,
                direction: 1,
                padding: None,
            },
            receiver: VpnTunnelReceiver {
                recv,
                key,
                counter: 0,
                direction: 1,
                padding_enabled: false,
            },
        })
    }

    /// Enable packet padding on both sender and receiver.
    pub fn set_padding(&mut self, config: PaddingConfig) {
        let enabled = config.enabled;
        self.sender.padding = Some(config);
        self.receiver.padding_enabled = enabled;
    }

    /// Split into independent sender and receiver for concurrent use.
    pub fn split(self) -> (VpnTunnelSender, VpnTunnelReceiver) {
        (self.sender, self.receiver)
    }
}

fn make_nonce(direction: u8, counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&(direction as u32).to_le_bytes());
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

impl VpnTunnelSender {
    /// Encrypt and send a packet over the tunnel.
    ///
    /// If padding is enabled, the plaintext becomes
    /// `[2B original_len][data][random_padding]` before encryption.
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        let nonce = make_nonce(self.direction, self.counter);
        self.counter += 1;

        let plaintext = if let Some(ref padding) = self.padding {
            if padding.enabled {
                padding.pad_packet(packet)
            } else {
                packet.to_vec()
            }
        } else {
            packet.to_vec()
        };

        let encrypted =
            cipher::encrypt(&plaintext, &self.key, &nonce, b"vpn").map_err(|_| TunError::Encryption)?;

        let len = (encrypted.len() as u16).to_be_bytes();
        self.send
            .write_all(&len)
            .await
            .map_err(|e| TunError::Transport(e.to_string()))?;
        self.send
            .write_all(&encrypted)
            .await
            .map_err(|e| TunError::Transport(e.to_string()))?;

        Ok(())
    }

    /// Enable or update padding configuration.
    pub fn set_padding(&mut self, config: PaddingConfig) {
        self.padding = Some(config);
    }
}

impl VpnTunnelReceiver {
    /// Receive and decrypt the next packet from the tunnel.
    ///
    /// If padding is enabled, strips the `[2B len][data][padding]` envelope.
    /// Dummy/keepalive packets (original_len == 0) are silently skipped.
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>, TunError> {
        loop {
            let mut len_buf = [0u8; 2];
            self.recv
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| TunError::Transport(e.to_string()))?;
            let len = u16::from_be_bytes(len_buf) as usize;

            let mut encrypted = vec![0u8; len];
            self.recv
                .read_exact(&mut encrypted)
                .await
                .map_err(|e| TunError::Transport(e.to_string()))?;

            // Peer sends with the opposite direction byte
            let peer_direction = 1 - self.direction;
            let nonce = make_nonce(peer_direction, self.counter);
            self.counter += 1;

            let decrypted =
                cipher::decrypt(&encrypted, &self.key, &nonce, b"vpn").map_err(|_| TunError::Decryption)?;

            if self.padding_enabled {
                match PaddingConfig::unpad_packet(&decrypted) {
                    Some(data) => return Ok(data),
                    None => continue, // Dummy packet — skip and read next
                }
            } else {
                return Ok(decrypted);
            }
        }
    }

    /// Enable or disable padding-aware receiving.
    pub fn set_padding_enabled(&mut self, enabled: bool) {
        self.padding_enabled = enabled;
    }
}
