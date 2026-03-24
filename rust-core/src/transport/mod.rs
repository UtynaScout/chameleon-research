#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy)]
pub struct TransportConfig {
    pub mtu: usize,
    pub mode: TransportMode,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mtu: 1514,
            mode: TransportMode::Udp,
        }
    }
}
