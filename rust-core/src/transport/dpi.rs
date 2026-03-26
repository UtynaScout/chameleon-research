//! DPI resistance configuration for research and detector testing.
//!
//! This module provides configurable TLS fingerprint presets, SNI injection,
//! ALPN control, and packet padding — all designed for testing DPI detectors
//! in a controlled lab environment.
//!
//! **Ethical disclaimer:** These features are intended exclusively for research
//! into network monitoring systems, not for circumventing lawful restrictions.

use rustls::crypto::ring;

// ---------------------------------------------------------------------------
// DPI profile (top-level configuration)
// ---------------------------------------------------------------------------

/// Complete DPI resistance profile for a VPN connection.
#[derive(Debug, Clone)]
pub struct DpiProfile {
    /// SNI to send in TLS Client Hello. `None` = use server IP (default).
    pub sni: Option<String>,
    /// ALPN protocols to advertise. Default: `["h3"]`.
    pub alpn: Vec<String>,
    /// TLS fingerprint preset controlling cipher suite and kx group order.
    pub fingerprint: FingerprintPreset,
    /// Packet padding configuration.
    pub padding: PaddingConfig,
    /// Traffic shaping profile.
    pub shaping: ShapingProfile,
}

impl Default for DpiProfile {
    fn default() -> Self {
        Self {
            sni: None,
            alpn: vec!["h3".into()],
            fingerprint: FingerprintPreset::RustlsDefault,
            padding: PaddingConfig::default(),
            shaping: ShapingProfile::None,
        }
    }
}

// ---------------------------------------------------------------------------
// TLS fingerprint presets
// ---------------------------------------------------------------------------

/// TLS fingerprint preset controlling cipher suite order, kx groups, and
/// protocol versions. The ordering of cipher suites is the primary
/// differentiator in JA3/JA4 fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintPreset {
    /// Default rustls ordering (easily identifiable as rustls).
    RustlsDefault,
    /// Chrome 130 cipher suite ordering.
    Chrome130,
    /// Firefox 120 cipher suite ordering.
    Firefox120,
}

impl FingerprintPreset {
    /// Parse from a string (used in TOML config).
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "rustls_default" | "rustls" => Ok(Self::RustlsDefault),
            "chrome_130" | "chrome" => Ok(Self::Chrome130),
            "firefox_120" | "firefox" => Ok(Self::Firefox120),
            other => Err(format!("unknown fingerprint preset: {other}")),
        }
    }

    /// Build a [`rustls::crypto::CryptoProvider`] matching this preset.
    ///
    /// The cipher suite and key exchange group ordering determines the
    /// JA3 fingerprint hash.
    pub fn crypto_provider(&self) -> rustls::crypto::CryptoProvider {
        match self {
            Self::RustlsDefault => ring::default_provider(),
            Self::Chrome130 => chrome_130_provider(),
            Self::Firefox120 => firefox_120_provider(),
        }
    }

    /// Human-readable description for logging / docs.
    pub fn description(&self) -> &'static str {
        match self {
            Self::RustlsDefault => "rustls default (identifiable)",
            Self::Chrome130 => "Chrome 130 cipher suite ordering",
            Self::Firefox120 => "Firefox 120 cipher suite ordering",
        }
    }

    /// Expected cipher suite IDs in Client Hello order (for test assertions).
    pub fn expected_cipher_ids(&self) -> Vec<u16> {
        match self {
            Self::RustlsDefault => vec![
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            ],
            Self::Chrome130 => vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            ],
            Self::Firefox120 => vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// Packet padding
// ---------------------------------------------------------------------------

/// Packet padding configuration.
///
/// When enabled, the encrypted payload becomes:
/// `[2B original_len BE][original_data][random_padding]`
///
/// The receiver reads `original_len` to strip padding. A zero-length
/// original indicates a dummy/keepalive packet (discarded by receiver).
#[derive(Debug, Clone)]
pub struct PaddingConfig {
    pub enabled: bool,
    pub mode: PaddingMode,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: PaddingMode::None,
        }
    }
}

/// Padding strategy for outgoing VPN packets.
#[derive(Debug, Clone)]
pub enum PaddingMode {
    /// No padding (backward compatible).
    None,
    /// Pad to the nearest value in `target_sizes`.
    Mss(Vec<usize>),
    /// Pad to a uniformly random size in `[min, max]`.
    Random { min_size: usize, max_size: usize },
    /// Pad to an exact fixed size.
    Fixed(usize),
}

impl PaddingConfig {
    /// Compute the target padded payload size for a packet of `data_len` bytes.
    ///
    /// The returned size is the total plaintext size including the 2-byte
    /// length prefix: `2 + data_len + padding_bytes`.
    pub fn padded_size(&self, data_len: usize) -> usize {
        let header = 2; // 2-byte original length prefix
        let min_size = header + data_len;

        if !self.enabled {
            return min_size;
        }

        match &self.mode {
            PaddingMode::None => min_size,
            PaddingMode::Mss(targets) => {
                // Find the smallest target >= min_size
                targets
                    .iter()
                    .copied()
                    .filter(|&t| t >= min_size)
                    .min()
                    .unwrap_or_else(|| targets.iter().copied().max().unwrap_or(min_size).max(min_size))
            }
            PaddingMode::Random { min_size: lo, max_size: hi } => {
                let lo = (*lo).max(min_size);
                let hi = (*hi).max(lo);
                // Deterministic for a given packet (use data_len as seed component)
                lo + (data_len % (hi - lo + 1))
            }
            PaddingMode::Fixed(size) => (*size).max(min_size),
        }
    }

    /// Build a padded plaintext: `[2B original_len BE][data][random_padding]`.
    pub fn pad_packet(&self, data: &[u8]) -> Vec<u8> {
        let target = self.padded_size(data.len());
        let mut buf = Vec::with_capacity(target);

        // 2-byte original data length (big-endian)
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        // Original data
        buf.extend_from_slice(data);
        // Random padding to reach target size
        while buf.len() < target {
            buf.push(rand::random::<u8>());
        }

        buf
    }

    /// Build a dummy/keepalive packet (original_len = 0).
    pub fn dummy_packet(&self, target_size: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(target_size.max(2));
        buf.extend_from_slice(&0u16.to_be_bytes()); // original_len = 0
        while buf.len() < target_size {
            buf.push(rand::random::<u8>());
        }
        buf
    }

    /// Strip padding from a decrypted payload.
    ///
    /// Returns `None` for dummy/keepalive packets (original_len == 0).
    pub fn unpad_packet(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 2 {
            return None;
        }
        let original_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if original_len == 0 {
            return None; // Dummy packet
        }
        if data.len() < 2 + original_len {
            return None; // Truncated
        }
        Some(data[2..2 + original_len].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Traffic shaping profiles
// ---------------------------------------------------------------------------

/// Traffic shaping profile for timing-based DPI resistance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapingProfile {
    /// No shaping — packets sent immediately.
    None,
    /// Mimic web browsing traffic patterns.
    Browsing,
    /// Mimic video streaming traffic patterns.
    Streaming,
}

impl ShapingProfile {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "none" | "" => Ok(Self::None),
            "browsing" | "browse" => Ok(Self::Browsing),
            "streaming" | "stream" => Ok(Self::Streaming),
            other => Err(format!("unknown shaping profile: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// CryptoProvider builders (fingerprint presets)
// ---------------------------------------------------------------------------

/// Chrome 130 cipher suite ordering.
///
/// Key differences from rustls default:
/// - TLS 1.3: AES-128-GCM first (rustls puts AES-256-GCM first)
/// - TLS 1.2: ECDHE_ECDSA before ECDHE_RSA, 128-bit before 256-bit
/// - CHACHA20 suites last (rustls interleaves them)
fn chrome_130_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            // TLS 1.3 (Chrome order: 128 → 256 → ChaCha)
            ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            // TLS 1.2 (Chrome order: ECDSA+128, RSA+128, ECDSA+256, RSA+256, ChaCha)
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ],
        kx_groups: vec![
            ring::kx_group::X25519,
            ring::kx_group::SECP256R1,
            ring::kx_group::SECP384R1,
        ],
        ..ring::default_provider()
    }
}

/// Firefox 120 cipher suite ordering.
///
/// Key differences from Chrome:
/// - TLS 1.3: ChaCha before AES-256
/// - TLS 1.2: ChaCha suites appear earlier (after AES-128)
fn firefox_120_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            // TLS 1.3 (Firefox order: 128 → ChaCha → 256)
            ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            // TLS 1.2 (Firefox order: ECDSA+128, RSA+128, ChaCha, then 256)
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![
            ring::kx_group::X25519,
            ring::kx_group::SECP256R1,
            ring::kx_group::SECP384R1,
        ],
        ..ring::default_provider()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_cipher_order_chrome() {
        let provider = FingerprintPreset::Chrome130.crypto_provider();
        let ids: Vec<u16> = provider
            .cipher_suites
            .iter()
            .map(|cs| u16::from(cs.suite()))
            .collect();
        assert_eq!(ids, FingerprintPreset::Chrome130.expected_cipher_ids());
        // Chrome puts AES-128 first
        assert_eq!(ids[0], 0x1301);
    }

    #[test]
    fn fingerprint_cipher_order_firefox() {
        let provider = FingerprintPreset::Firefox120.crypto_provider();
        let ids: Vec<u16> = provider
            .cipher_suites
            .iter()
            .map(|cs| u16::from(cs.suite()))
            .collect();
        assert_eq!(ids, FingerprintPreset::Firefox120.expected_cipher_ids());
        // Firefox puts ChaCha before AES-256
        assert_eq!(ids[1], 0x1303);
    }

    #[test]
    fn fingerprint_cipher_order_rustls() {
        let provider = FingerprintPreset::RustlsDefault.crypto_provider();
        let ids: Vec<u16> = provider
            .cipher_suites
            .iter()
            .map(|cs| u16::from(cs.suite()))
            .collect();
        assert_eq!(ids, FingerprintPreset::RustlsDefault.expected_cipher_ids());
        // rustls puts AES-256 first
        assert_eq!(ids[0], 0x1302);
    }

    #[test]
    fn chrome_differs_from_rustls() {
        let chrome = FingerprintPreset::Chrome130.expected_cipher_ids();
        let rustls_ids = FingerprintPreset::RustlsDefault.expected_cipher_ids();
        assert_ne!(chrome, rustls_ids, "Chrome must differ from rustls default");
    }

    #[test]
    fn firefox_differs_from_chrome() {
        let ff = FingerprintPreset::Firefox120.expected_cipher_ids();
        let chrome = FingerprintPreset::Chrome130.expected_cipher_ids();
        assert_ne!(ff, chrome, "Firefox must differ from Chrome");
    }

    #[test]
    fn padding_disabled_no_change() {
        let cfg = PaddingConfig::default();
        assert!(!cfg.enabled);
        let padded = cfg.pad_packet(b"hello");
        // 2-byte header + 5 bytes data, no padding
        assert_eq!(padded.len(), 7);
        assert_eq!(&padded[..2], &(5u16).to_be_bytes());
        assert_eq!(&padded[2..], b"hello");
    }

    #[test]
    fn padding_mss_pads_correctly() {
        let cfg = PaddingConfig {
            enabled: true,
            mode: PaddingMode::Mss(vec![64, 128, 256]),
        };
        // 10 bytes data + 2 header = 12; nearest MSS >= 12 is 64
        let padded = cfg.pad_packet(&[0xAB; 10]);
        assert_eq!(padded.len(), 64);
        let original_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
        assert_eq!(original_len, 10);
        assert!(padded[2..12].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn padding_fixed_pads_correctly() {
        let cfg = PaddingConfig {
            enabled: true,
            mode: PaddingMode::Fixed(200),
        };
        let padded = cfg.pad_packet(&[1, 2, 3]);
        assert_eq!(padded.len(), 200);
        assert_eq!(PaddingConfig::unpad_packet(&padded), Some(vec![1, 2, 3]));
    }

    #[test]
    fn padding_unpad_roundtrip() {
        let cfg = PaddingConfig {
            enabled: true,
            mode: PaddingMode::Mss(vec![128, 256, 512]),
        };
        let data = b"test packet data for roundtrip";
        let padded = cfg.pad_packet(data);
        let unpadded = PaddingConfig::unpad_packet(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn padding_dummy_packet() {
        let cfg = PaddingConfig {
            enabled: true,
            mode: PaddingMode::Fixed(100),
        };
        let dummy = cfg.dummy_packet(100);
        assert_eq!(dummy.len(), 100);
        assert_eq!(u16::from_be_bytes([dummy[0], dummy[1]]), 0);
        assert!(PaddingConfig::unpad_packet(&dummy).is_none());
    }

    #[test]
    fn fingerprint_from_str() {
        assert_eq!(
            FingerprintPreset::from_str("chrome_130").unwrap(),
            FingerprintPreset::Chrome130
        );
        assert_eq!(
            FingerprintPreset::from_str("firefox").unwrap(),
            FingerprintPreset::Firefox120
        );
        assert_eq!(
            FingerprintPreset::from_str("rustls").unwrap(),
            FingerprintPreset::RustlsDefault
        );
        assert!(FingerprintPreset::from_str("unknown").is_err());
    }

    #[test]
    fn shaping_from_str() {
        assert_eq!(ShapingProfile::from_str("none").unwrap(), ShapingProfile::None);
        assert_eq!(
            ShapingProfile::from_str("browsing").unwrap(),
            ShapingProfile::Browsing
        );
        assert_eq!(
            ShapingProfile::from_str("streaming").unwrap(),
            ShapingProfile::Streaming
        );
        assert!(ShapingProfile::from_str("unknown").is_err());
    }
}
