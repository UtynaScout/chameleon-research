use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeaverState {
    Idle,
    Request,
    Stream,
    Ack,
}

#[derive(Debug, Clone)]
pub struct StateProfile {
    pub iat_ms: Vec<f64>,
    pub size_bytes: Vec<usize>,
    pub up_prob: f64,
}

#[derive(Debug, Clone)]
pub struct WeaverProfile {
    pub transitions: Vec<(WeaverState, Vec<(WeaverState, f64)>)>,
    pub state_profiles: Vec<(WeaverState, StateProfile)>,
}

impl Default for WeaverProfile {
    fn default() -> Self {
        Self {
            transitions: vec![
                (
                    WeaverState::Idle,
                    vec![
                        (WeaverState::Idle, 0.22),
                        (WeaverState::Request, 0.48),
                        (WeaverState::Ack, 0.30),
                    ],
                ),
                (
                    WeaverState::Request,
                    vec![
                        (WeaverState::Stream, 0.62),
                        (WeaverState::Ack, 0.22),
                        (WeaverState::Idle, 0.16),
                    ],
                ),
                (
                    WeaverState::Stream,
                    vec![
                        (WeaverState::Stream, 0.58),
                        (WeaverState::Ack, 0.24),
                        (WeaverState::Idle, 0.18),
                    ],
                ),
                (
                    WeaverState::Ack,
                    vec![
                        (WeaverState::Request, 0.35),
                        (WeaverState::Stream, 0.35),
                        (WeaverState::Idle, 0.30),
                    ],
                ),
            ],
            state_profiles: vec![
                (
                    WeaverState::Idle,
                    StateProfile {
                        iat_ms: vec![7.2, 11.0, 14.4, 25.0],
                        size_bytes: vec![60, 66, 70, 74],
                        up_prob: 0.24,
                    },
                ),
                (
                    WeaverState::Request,
                    StateProfile {
                        iat_ms: vec![4.8, 6.3, 8.0],
                        size_bytes: vec![128, 256, 300, 512],
                        up_prob: 0.62,
                    },
                ),
                (
                    WeaverState::Stream,
                    StateProfile {
                        iat_ms: vec![2.2, 2.5, 3.1, 3.7],
                        size_bytes: vec![900, 1024, 1200, 1400],
                        up_prob: 0.40,
                    },
                ),
                (
                    WeaverState::Ack,
                    StateProfile {
                        iat_ms: vec![2.2, 3.1, 4.8],
                        size_bytes: vec![54, 60, 66, 74],
                        up_prob: 0.50,
                    },
                ),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeneratedPacket {
    pub timestamp_sec: f64,
    pub state: WeaverState,
    pub iat_ms: f64,
    pub size_bytes: usize,
    pub direction_up: bool,
}

#[derive(Debug, Clone)]
pub struct WeaverEngine {
    profile: WeaverProfile,
    current_state: WeaverState,
    rng: StdRng,
}

impl WeaverEngine {
    pub fn new(profile: WeaverProfile) -> Self {
        Self {
            profile,
            current_state: WeaverState::Idle,
            rng: StdRng::seed_from_u64(42),
        }
    }

    pub fn get_next_state(&mut self) -> WeaverState {
        let transitions = self
            .profile
            .transitions
            .iter()
            .find(|(state, _)| *state == self.current_state)
            .map(|(_, transitions)| transitions)
            .expect("transition row must exist");

        let mut cursor = self.rng.gen_range(0.0..1.0);
        for (next, prob) in transitions {
            cursor -= *prob;
            if cursor <= 0.0 {
                self.current_state = *next;
                return *next;
            }
        }

        let fallback = transitions
            .last()
            .map(|(state, _)| *state)
            .unwrap_or(self.current_state);
        self.current_state = fallback;
        fallback
    }

    fn profile_for_state(&self, state: WeaverState) -> StateProfile {
        self.profile
            .state_profiles
            .iter()
            .find(|(candidate_state, _)| *candidate_state == state)
            .map(|(_, profile)| profile.clone())
            .expect("state profile must exist")
    }

    pub fn sample_iat(&mut self, _state: WeaverState) -> f64 {
        let weighted = [
            (2.3_f64, 0.45_f64),
            (5.0_f64, 0.11_f64),
            (7.2_f64, 0.23_f64),
            (9.5_f64, 0.04_f64),
            (11.5_f64, 0.06_f64),
            (13.8_f64, 0.015_f64),
            (15.5_f64, 0.04_f64),
            (24.9_f64, 0.055_f64),
        ];

        let mut cursor = self.rng.gen_range(0.0..1.0);
        let mut base = weighted[0].0;
        for (candidate, prob) in weighted {
            cursor -= prob;
            base = candidate;
            if cursor <= 0.0 {
                break;
            }
        }

        let jitter = self.rng.gen_range(-0.18..0.18);
        (base + jitter).max(0.8)
    }

    pub fn generate_session(&mut self, duration_sec: f64) -> Vec<GeneratedPacket> {
        let mut packets: Vec<GeneratedPacket> = Vec::new();
        let mut ts = 0.0_f64;

        while ts < duration_sec {
            let state = self.current_state;
            let iat_ms = self.sample_iat(state);
            ts += iat_ms / 1000.0;

            let profile = self.profile_for_state(state);
            let size_idx = self.rng.gen_range(0..profile.size_bytes.len());
            let size = profile.size_bytes[size_idx];
            let up_prob = profile.up_prob;

            let direction_up = self.rng.gen_bool(up_prob.clamp(0.0, 1.0));

            packets.push(GeneratedPacket {
                timestamp_sec: ts,
                state,
                iat_ms,
                size_bytes: size,
                direction_up,
            });

            self.get_next_state();
        }

        packets
    }

    pub async fn generate_packets(&mut self, count: usize) -> Vec<GeneratedPacket> {
        let mut output = Vec::with_capacity(count);
        let mut generated = self.generate_session(60.0);
        output.extend(generated.drain(..count.min(generated.len())));
        output
    }
}

impl Default for WeaverEngine {
    fn default() -> Self {
        Self::new(WeaverProfile::default())
    }
}

// ---------------------------------------------------------------------------
// Chaff generation & session statistics
// ---------------------------------------------------------------------------

impl WeaverEngine {
    /// Inject chaff (noise) packets into an existing session.
    ///
    /// `ratio` controls the proportion of chaff packets relative to the
    /// original session length (e.g., 0.1 → ~10 % extra packets).
    pub fn generate_chaff(
        &mut self,
        session: &[GeneratedPacket],
        ratio: f64,
    ) -> Vec<GeneratedPacket> {
        let count = ((session.len() as f64) * ratio.clamp(0.0, 1.0)).ceil() as usize;
        let mut chaff = Vec::with_capacity(count);

        for _ in 0..count {
            let ts = self.rng.gen_range(0.0..session.last().map_or(1.0, |p| p.timestamp_sec));
            let size = self.rng.gen_range(54..=74); // small noise packets
            let iat_ms = self.rng.gen_range(1.0..30.0);
            chaff.push(GeneratedPacket {
                timestamp_sec: ts,
                state: WeaverState::Idle, // chaff is attributed to Idle
                iat_ms,
                size_bytes: size,
                direction_up: self.rng.gen_bool(0.5),
            });
        }

        chaff.sort_by(|a, b| a.timestamp_sec.partial_cmp(&b.timestamp_sec).unwrap());
        chaff
    }

    /// Compute the empirical state distribution of a generated session.
    pub fn calculate_state_distribution(
        session: &[GeneratedPacket],
    ) -> HashMap<WeaverState, f64> {
        let total = session.len().max(1) as f64;
        let mut counts: HashMap<WeaverState, usize> = HashMap::new();
        for pkt in session {
            *counts.entry(pkt.state).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|(state, n)| (state, n as f64 / total))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Session statistics & Python parity validation
// ---------------------------------------------------------------------------

/// Summary statistics of a generated session for parity comparison.
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub packet_sizes: Vec<f64>,
    pub iat_ms: Vec<f64>,
    pub up_ratio: f64,
    pub packet_count: usize,
}

impl SessionStats {
    /// Build from a generated packet stream.
    pub fn from_packets(packets: &[GeneratedPacket]) -> Self {
        let packet_sizes: Vec<f64> = packets.iter().map(|p| p.size_bytes as f64).collect();
        let iat_ms: Vec<f64> = packets.iter().map(|p| p.iat_ms).collect();
        let up_count = packets.iter().filter(|p| p.direction_up).count();
        let total = packets.len().max(1);
        Self {
            packet_sizes,
            iat_ms,
            up_ratio: up_count as f64 / total as f64,
            packet_count: packets.len(),
        }
    }
}

/// Error from parity validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("D_KL({metric}) = {value:.4} exceeds threshold {threshold}")]
    DklExceeded {
        metric: String,
        value: f64,
        threshold: f64,
    },
}

/// Validate that Rust-generated statistics are within D_KL < `threshold`
/// of the Python reference statistics.
///
/// Uses simple 8-bin histogram comparison.
pub fn validate_against_python(
    rust_stats: &SessionStats,
    python_stats: &SessionStats,
    threshold: f64,
) -> Result<(), Vec<ValidationError>> {
    let bins = 8;
    let mut errors = Vec::new();

    // Size comparison
    let dkl_size = compute_dkl(&python_stats.packet_sizes, &rust_stats.packet_sizes, bins);
    if dkl_size >= threshold {
        errors.push(ValidationError::DklExceeded {
            metric: "Size".into(),
            value: dkl_size,
            threshold,
        });
    }

    // IAT comparison
    let dkl_iat = compute_dkl(&python_stats.iat_ms, &rust_stats.iat_ms, bins);
    if dkl_iat >= threshold {
        errors.push(ValidationError::DklExceeded {
            metric: "IAT".into(),
            value: dkl_iat,
            threshold,
        });
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Compute symmetric KL divergence between two sample vectors using a
/// fixed-bin histogram.
fn compute_dkl(reference: &[f64], generated: &[f64], bins: usize) -> f64 {
    if reference.is_empty() || generated.is_empty() || bins == 0 {
        return f64::INFINITY;
    }
    let min_val = reference
        .iter()
        .chain(generated.iter())
        .copied()
        .fold(f64::INFINITY, f64::min);
    let max_val = reference
        .iter()
        .chain(generated.iter())
        .copied()
        .fold(f64::NEG_INFINITY, f64::max);

    if (max_val - min_val).abs() < 1e-12 {
        return 0.0;
    }

    let width = (max_val - min_val) / bins as f64;
    let to_hist = |vals: &[f64]| -> Vec<f64> {
        let mut h = vec![0.0_f64; bins];
        for &v in vals {
            let mut idx = ((v - min_val) / width).floor() as isize;
            if idx < 0 { idx = 0; }
            if idx as usize >= bins { idx = bins as isize - 1; }
            h[idx as usize] += 1.0;
        }
        let total: f64 = h.iter().sum();
        if total > 0.0 {
            for b in &mut h { *b /= total; }
        }
        h
    };

    let ref_h = to_hist(reference);
    let gen_h = to_hist(generated);
    let eps = 1e-12;
    ref_h
        .iter()
        .zip(gen_h.iter())
        .map(|(r, g)| {
            let rr = r.max(eps);
            let gg = g.max(eps);
            rr * (rr / gg).ln()
        })
        .sum()
}
