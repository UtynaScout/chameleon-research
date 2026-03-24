use rand::Rng;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone)]
pub struct GeneratedPacket {
    pub iat_ms: u64,
    pub size_bytes: usize,
    pub direction_up: bool,
}

#[derive(Debug, Clone)]
pub struct WeaverEngine {
    ack_ratio: f64,
}

impl Default for WeaverEngine {
    fn default() -> Self {
        Self { ack_ratio: 0.44 }
    }
}

impl WeaverEngine {
    pub async fn generate_packets(&mut self, count: usize) -> Vec<GeneratedPacket> {
        let mut out = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            let is_ack = rng.gen_bool(self.ack_ratio.clamp(0.0, 1.0));
            let size = if is_ack {
                rng.gen_range(54..=74)
            } else {
                rng.gen_range(120..=1450)
            };
            let iat = if is_ack {
                rng.gen_range(3..=12)
            } else {
                rng.gen_range(1..=40)
            };
            sleep(Duration::from_millis(iat)).await;

            out.push(GeneratedPacket {
                iat_ms: iat,
                size_bytes: size,
                direction_up: rng.gen_bool(0.5),
            });
        }

        out
    }
}
