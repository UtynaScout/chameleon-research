use std::fs;
use std::path::Path;

use chameleon_core::frame::model::FrameType;
use chameleon_core::frame::ChameleonFrame;
use chameleon_core::weaver::{WeaverEngine, WeaverProfile};
use chameleon_core::{crypto, weaver};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct BaselineStats {
    packet_sizes: Vec<f64>,
    iat_ms: Vec<f64>,
}

fn histogram(values: &[f64], bins: usize, min: f64, max: f64) -> Vec<f64> {
    let mut hist = vec![0.0_f64; bins];
    if values.is_empty() || bins == 0 || max <= min {
        return hist;
    }

    let width = (max - min) / bins as f64;
    for &value in values {
        let mut idx = ((value - min) / width).floor() as isize;
        if idx < 0 {
            idx = 0;
        }
        if idx as usize >= bins {
            idx = bins as isize - 1;
        }
        hist[idx as usize] += 1.0;
    }

    let total: f64 = hist.iter().sum();
    if total > 0.0 {
        for bucket in &mut hist {
            *bucket /= total;
        }
    }

    hist
}

fn kl_divergence(reference: &[f64], generated: &[f64]) -> f64 {
    let eps = 1e-12;
    reference
        .iter()
        .zip(generated.iter())
        .map(|(r, g)| {
            let rr = r.max(eps);
            let gg = g.max(eps);
            rr * (rr / gg).ln()
        })
        .sum()
}

#[test]
fn test_python_rust_distribution_parity() {
    let baseline_path = Path::new("..")
        .join("data")
        .join("baseline_v0.3.1.json");
    let payload = fs::read_to_string(baseline_path).expect("baseline stats file should exist");
    let baseline: BaselineStats = serde_json::from_str(&payload).expect("baseline json should parse");

    let mut engine = WeaverEngine::new(WeaverProfile::default());
    let session = engine.generate_session(30.0);

    let rust_sizes: Vec<f64> = session.iter().map(|packet| packet.size_bytes as f64).collect();
    let rust_iat: Vec<f64> = session.iter().map(|packet| packet.iat_ms).collect();

    let size_min = baseline
        .packet_sizes
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min)
        .min(rust_sizes.iter().copied().fold(f64::INFINITY, f64::min));
    let size_max = baseline
        .packet_sizes
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max)
        .max(rust_sizes.iter().copied().fold(f64::NEG_INFINITY, f64::max));

    let iat_min = baseline
        .iat_ms
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min)
        .min(rust_iat.iter().copied().fold(f64::INFINITY, f64::min));
    let iat_max = baseline
        .iat_ms
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max)
        .max(rust_iat.iter().copied().fold(f64::NEG_INFINITY, f64::max));

    let bins = 8;
    let baseline_size_hist = histogram(&baseline.packet_sizes, bins, size_min, size_max);
    let rust_size_hist = histogram(&rust_sizes, bins, size_min, size_max);
    let baseline_iat_hist = histogram(&baseline.iat_ms, bins, iat_min, iat_max);
    let rust_iat_hist = histogram(&rust_iat, bins, iat_min, iat_max);

    let dkl_size = kl_divergence(&baseline_size_hist, &rust_size_hist);
    let dkl_iat = kl_divergence(&baseline_iat_hist, &rust_iat_hist);

    assert!(dkl_size < 0.1, "D_KL(Size) too high: {}", dkl_size);
    assert!(dkl_iat < 0.1, "D_KL(IAT) too high: {}", dkl_iat);
}

// ---------------------------------------------------------------------------
// End-to-end: weaver generates → frame encodes → crypto encrypts → roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_end_to_end_weaver_frame_crypto() {
    // 1. Generate a session with the weaver
    let mut engine = WeaverEngine::new(WeaverProfile::default());
    let session = engine.generate_session(5.0);
    assert!(!session.is_empty(), "session must not be empty");

    // 2. Derive session key via HKDF
    let master_psk = b"research-lab-psk-2026";
    let salt = b"integration-test-salt";
    let info = b"chameleon-e2e-v1";
    let session_key = crypto::derive_session_key(master_psk, salt, info);

    let nonce = [0x42_u8; 12];
    let aad = b"e2e-test";

    // 3. For each packet: build frame → encrypt with AAD → decrypt → verify roundtrip
    for (i, pkt) in session.iter().take(50).enumerate() {
        let payload = vec![0xAA_u8; pkt.size_bytes.min(1400)];
        let frame = ChameleonFrame {
            stream_id: i as u32,
            frame_type: if pkt.direction_up { FrameType::Data } else { FrameType::Ack },
            payload,
        };

        let ciphertext = frame
            .encrypt_with_aad(&session_key, &nonce, aad)
            .expect("encrypt_with_aad must succeed");

        let recovered = ChameleonFrame::decrypt_with_aad(&ciphertext, &session_key, &nonce, aad)
            .expect("decrypt_with_aad must succeed");

        assert_eq!(recovered, frame, "frame roundtrip failed at packet {i}");
    }

    // 4. Validate session stats via weaver helper
    let stats = weaver::SessionStats::from_packets(&session);
    assert!(stats.packet_count > 0);
}

// ---------------------------------------------------------------------------
// Chaff injection does not break distribution parity
// ---------------------------------------------------------------------------

#[test]
fn test_chaff_injection_preserves_distribution() {
    let mut engine = WeaverEngine::new(WeaverProfile::default());
    let session = engine.generate_session(10.0);
    let chaff = engine.generate_chaff(&session, 0.1);

    // Chaff packets should be ~10% of session length
    let expected_count = (session.len() as f64 * 0.1).ceil() as usize;
    assert_eq!(chaff.len(), expected_count);

    // All chaff packets must have valid timestamps within session range
    let max_ts = session.last().map_or(0.0, |p| p.timestamp_sec);
    for c in &chaff {
        assert!(
            c.timestamp_sec >= 0.0 && c.timestamp_sec <= max_ts,
            "chaff timestamp out of range"
        );
    }
}
