//! Keep-alive mechanism for VPN tunnel idle connections.
//!
//! Sends periodic dummy packets through the encrypted tunnel to prevent
//! NAT middleboxes from dropping the UDP mapping. The receiver side
//! already silently discards dummy packets (original_len == 0 in the
//! padding layer).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::debug;

/// Default keep-alive interval in seconds.
pub const DEFAULT_KEEPALIVE_INTERVAL_SECS: u64 = 25;

/// Keep-alive sender that periodically injects dummy packets.
///
/// Works with both raw `VpnTunnelSender` and `TrafficShaper` —
/// it sends empty payloads through a channel, and the VPN tunnel's
/// padding layer handles the encoding (2-byte zero length prefix).
pub struct KeepaliveHandle {
    alive: Arc<AtomicBool>,
}

impl KeepaliveHandle {
    /// Stop the keep-alive task.
    pub fn stop(&self) {
        self.alive.store(false, Ordering::Relaxed);
    }
}

impl Drop for KeepaliveHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn a keep-alive task that sends dummy (empty) packets at `interval`.
///
/// Returns a handle that can be used to stop the task, and the receiver
/// channel that should be polled in the main send loop.
///
/// The dummy packets are sent as `Vec<u8>` with length 0, which the
/// `VpnTunnelSender::send_packet` encodes as a padding-only frame
/// that the receiver skips.
pub fn spawn_keepalive(
    interval: Duration,
) -> (KeepaliveHandle, mpsc::Receiver<()>) {
    let alive = Arc::new(AtomicBool::new(true));
    let (tx, rx) = mpsc::channel(4);

    let alive_clone = Arc::clone(&alive);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the first immediate tick
        tick.tick().await;

        loop {
            tick.tick().await;
            if !alive_clone.load(Ordering::Relaxed) {
                break;
            }
            if tx.send(()).await.is_err() {
                break; // Channel closed — tunnel is gone
            }
            debug!("keepalive ping sent");
        }
    });

    let handle = KeepaliveHandle { alive };
    (handle, rx)
}
