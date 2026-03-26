//! Traffic shaping engine for timing-based DPI resistance.
//!
//! The [`TrafficShaper`] wraps a [`VpnTunnelSender`] and re-schedules
//! outgoing packets to match a statistical traffic profile (browsing,
//! streaming, etc.). It uses the Weaver engine to generate realistic
//! inter-arrival times.
//!
//! When no real traffic is pending but the profile dictates activity,
//! dummy/keepalive packets are injected to maintain the pattern.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, trace};

use crate::transport::dpi::{PaddingConfig, PaddingMode, ShapingProfile};
use crate::tun::{TunError, VpnTunnelSender};
use crate::weaver::{WeaverEngine, WeaverProfile, WeaverState};

// ---------------------------------------------------------------------------
// Streaming profile (distinct from browsing / default)
// ---------------------------------------------------------------------------

/// Build a Weaver profile that mimics video streaming traffic.
///
/// Characteristics vs browsing:
/// - Much higher Stream→Stream probability (long bursts)
/// - Larger packet sizes in Stream state
/// - More consistent timing (lower IAT variance)
fn streaming_weaver_profile() -> WeaverProfile {
    use crate::weaver::StateProfile;

    WeaverProfile {
        transitions: vec![
            (
                WeaverState::Idle,
                vec![
                    (WeaverState::Stream, 0.70),
                    (WeaverState::Ack, 0.20),
                    (WeaverState::Idle, 0.10),
                ],
            ),
            (
                WeaverState::Request,
                vec![
                    (WeaverState::Stream, 0.80),
                    (WeaverState::Ack, 0.15),
                    (WeaverState::Idle, 0.05),
                ],
            ),
            (
                WeaverState::Stream,
                vec![
                    (WeaverState::Stream, 0.85),
                    (WeaverState::Ack, 0.10),
                    (WeaverState::Idle, 0.05),
                ],
            ),
            (
                WeaverState::Ack,
                vec![
                    (WeaverState::Stream, 0.70),
                    (WeaverState::Request, 0.20),
                    (WeaverState::Idle, 0.10),
                ],
            ),
        ],
        state_profiles: vec![
            (
                WeaverState::Idle,
                StateProfile {
                    iat_ms: vec![5.0, 10.0, 15.0],
                    size_bytes: vec![60, 66, 74],
                    up_prob: 0.15,
                },
            ),
            (
                WeaverState::Request,
                StateProfile {
                    iat_ms: vec![3.0, 5.0, 7.0],
                    size_bytes: vec![128, 256, 512],
                    up_prob: 0.55,
                },
            ),
            (
                WeaverState::Stream,
                StateProfile {
                    iat_ms: vec![1.5, 2.0, 2.5, 3.0],
                    size_bytes: vec![1200, 1350, 1400, 1500],
                    up_prob: 0.20,
                },
            ),
            (
                WeaverState::Ack,
                StateProfile {
                    iat_ms: vec![2.0, 3.0, 4.0],
                    size_bytes: vec![54, 60, 66],
                    up_prob: 0.50,
                },
            ),
        ],
    }
}

// ---------------------------------------------------------------------------
// TrafficShaper
// ---------------------------------------------------------------------------

/// Wraps a [`VpnTunnelSender`] to re-schedule packets according to a
/// statistical traffic profile.
///
/// Packets are enqueued via [`send()`](TrafficShaper::send) and drained
/// by a background tokio task at intervals drawn from the Weaver engine.
pub struct TrafficShaper {
    tx: mpsc::Sender<Vec<u8>>,
    _task: tokio::task::JoinHandle<()>,
}

impl TrafficShaper {
    /// Create a new traffic shaper.
    ///
    /// - `sender`: the raw VPN tunnel sender (packets will be sent here).
    /// - `profile`: the shaping profile to mimic.
    /// - `padding`: padding config (needed for dummy packets).
    ///
    /// If `profile` is [`ShapingProfile::None`], packets are forwarded
    /// immediately with no delay.
    pub fn new(
        sender: VpnTunnelSender,
        profile: &ShapingProfile,
        padding: PaddingConfig,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(512);

        let profile = profile.clone();
        let task = tokio::spawn(async move {
            shaping_loop(sender, rx, &profile, padding).await;
        });

        Self { tx, _task: task }
    }

    /// Enqueue a packet for shaped transmission.
    pub async fn send(&self, packet: Vec<u8>) -> Result<(), TunError> {
        self.tx
            .send(packet)
            .await
            .map_err(|_| TunError::Transport("shaper channel closed".into()))
    }
}

/// Background loop that drains the send queue at profiled intervals.
async fn shaping_loop(
    mut sender: VpnTunnelSender,
    mut rx: mpsc::Receiver<Vec<u8>>,
    profile: &ShapingProfile,
    padding: PaddingConfig,
) {
    if *profile == ShapingProfile::None {
        // No shaping — forward immediately
        while let Some(pkt) = rx.recv().await {
            if sender.send_packet(&pkt).await.is_err() {
                break;
            }
        }
        return;
    }

    let weaver_profile = match profile {
        ShapingProfile::Browsing => WeaverProfile::default(),
        ShapingProfile::Streaming => streaming_weaver_profile(),
        ShapingProfile::None => unreachable!(),
    };
    let mut engine = WeaverEngine::new(weaver_profile);

    // Packet queue for buffering between timer ticks
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();

    loop {
        // Determine timing for next send event
        let state = engine.get_next_state();
        let iat_ms = engine.sample_iat(state);
        let delay = Duration::from_micros((iat_ms * 1000.0) as u64);

        // Wait for the profiled interval
        tokio::time::sleep(delay).await;

        // Drain any packets that arrived during the wait
        while let Ok(pkt) = rx.try_recv() {
            queue.push_back(pkt);
        }

        // Send one packet (real or dummy)
        if let Some(pkt) = queue.pop_front() {
            trace!(state = ?state, size = pkt.len(), "shaped: real packet");
            if sender.send_packet(&pkt).await.is_err() {
                break;
            }
        } else if matches!(state, WeaverState::Request | WeaverState::Stream) {
            // No real packet but profile says we should have traffic.
            // Only inject dummies if padding is enabled.
            if padding.enabled {
                let target_size = match &padding.mode {
                    PaddingMode::None => 64,
                    PaddingMode::Mss(sizes) => *sizes.first().unwrap_or(&64),
                    PaddingMode::Fixed(s) => *s,
                    PaddingMode::Random { min_size, .. } => *min_size,
                };
                let dummy = padding.dummy_packet(target_size);
                trace!(state = ?state, size = dummy.len(), "shaped: dummy packet");
                if sender.send_packet(&dummy).await.is_err() {
                    break;
                }
            }
        } else {
            debug!(state = ?state, "shaped: idle tick (no packet)");
        }

        // Check if sender is still alive
        if rx.is_closed() && queue.is_empty() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_profile_is_valid() {
        let profile = streaming_weaver_profile();
        // Verify all states have transitions
        assert_eq!(profile.transitions.len(), 4);
        assert_eq!(profile.state_profiles.len(), 4);

        // Verify transition probabilities sum to ~1.0
        for (_, transitions) in &profile.transitions {
            let sum: f64 = transitions.iter().map(|(_, p)| p).sum();
            assert!((sum - 1.0).abs() < 0.01, "probabilities should sum to 1.0");
        }
    }

    #[test]
    fn streaming_has_high_stream_continuity() {
        let profile = streaming_weaver_profile();
        let stream_transitions = profile
            .transitions
            .iter()
            .find(|(s, _)| *s == WeaverState::Stream)
            .unwrap();
        let self_prob = stream_transitions
            .1
            .iter()
            .find(|(s, _)| *s == WeaverState::Stream)
            .unwrap()
            .1;
        assert!(
            self_prob >= 0.80,
            "streaming should stay in Stream state ≥80% of the time"
        );
    }
}
