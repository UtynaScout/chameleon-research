//! Performance benchmarks for chameleon-core (Phase 4.0).
//!
//! Run with: `cargo bench`
//!
//! Reports are generated in `target/criterion/`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use chameleon_core::crypto::cipher::{decrypt, encrypt};
use chameleon_core::crypto::hkdf::{derive_session_key, rotate_key};
use chameleon_core::frame::model::FrameType;
use chameleon_core::frame::ChameleonFrame;
use chameleon_core::weaver::{SessionStats, WeaverEngine, WeaverProfile};

// ---------------------------------------------------------------------------
// Crypto benchmarks
// ---------------------------------------------------------------------------

fn bench_hkdf_derive(c: &mut Criterion) {
    c.bench_function("hkdf_derive_session_key", |b| {
        b.iter(|| {
            derive_session_key(
                black_box(b"my-psk-material"),
                black_box(b"random-salt-value"),
                black_box(b"session-info"),
            )
        })
    });
}

fn bench_key_rotation(c: &mut Criterion) {
    let key = derive_session_key(b"psk", b"salt", b"info");
    c.bench_function("hkdf_rotate_key", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            rotate_key(black_box(&key), black_box(counter))
        })
    });
}

fn bench_chacha20_encrypt(c: &mut Criterion) {
    let key = derive_session_key(b"psk", b"salt", b"bench");
    let nonce = [0x42u8; 12];
    let aad = b"benchmark-aad";

    let mut group = c.benchmark_group("chacha20_encrypt");

    for size in [64, 256, 1024, 4096, 8192] {
        let plaintext = vec![0xAAu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, data| {
            b.iter(|| encrypt(black_box(data), black_box(&key), black_box(&nonce), black_box(aad)))
        });
    }

    group.finish();
}

fn bench_chacha20_decrypt(c: &mut Criterion) {
    let key = derive_session_key(b"psk", b"salt", b"bench");
    let nonce = [0x42u8; 12];
    let aad = b"benchmark-aad";

    let mut group = c.benchmark_group("chacha20_decrypt");

    for size in [64, 256, 1024, 4096, 8192] {
        let plaintext = vec![0xAAu8; size];
        let ciphertext = encrypt(&plaintext, &key, &nonce, aad).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &ciphertext,
            |b, data| {
                b.iter(|| {
                    decrypt(black_box(data), black_box(&key), black_box(&nonce), black_box(aad))
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Frame benchmarks
// ---------------------------------------------------------------------------

fn bench_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_encode");

    for size in [64, 256, 1024, 4096] {
        let frame = ChameleonFrame {
            stream_id: 1,
            frame_type: FrameType::Data,
            payload: vec![0xBB; size],
        };
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &frame, |b, f| {
            b.iter(|| black_box(f).encode())
        });
    }

    group.finish();
}

fn bench_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_decode");

    for size in [64, 256, 1024, 4096] {
        let frame = ChameleonFrame {
            stream_id: 1,
            frame_type: FrameType::Data,
            payload: vec![0xBB; size],
        };
        let encoded = frame.encode();
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &encoded, |b, data| {
            b.iter(|| ChameleonFrame::decode(black_box(data)))
        });
    }

    group.finish();
}

fn bench_frame_encrypt_decrypt(c: &mut Criterion) {
    let key = derive_session_key(b"psk", b"salt", b"bench");
    let nonce = [0x01u8; 12];
    let aad = b"bench-aad";

    let mut group = c.benchmark_group("frame_encrypt_decrypt");

    for size in [64, 256, 1024, 4096] {
        let frame = ChameleonFrame {
            stream_id: 1,
            frame_type: FrameType::Data,
            payload: vec![0xCC; size],
        };

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt", size),
            &frame,
            |b, f| {
                b.iter(|| f.encrypt_with_aad(black_box(&key), black_box(&nonce), black_box(aad)))
            },
        );

        let encrypted = frame.encrypt_with_aad(&key, &nonce, aad).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt", size),
            &encrypted,
            |b, ct| {
                b.iter(|| {
                    ChameleonFrame::decrypt_with_aad(
                        black_box(ct),
                        black_box(&key),
                        black_box(&nonce),
                        black_box(aad),
                    )
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Weaver benchmarks
// ---------------------------------------------------------------------------

fn bench_weaver_generate_session(c: &mut Criterion) {
    let mut group = c.benchmark_group("weaver_generate_session");

    for duration in [1.0, 5.0, 10.0, 30.0] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{duration}s")),
            &duration,
            |b, &dur| {
                b.iter(|| {
                    let mut engine = WeaverEngine::new(WeaverProfile::default());
                    engine.generate_session(black_box(dur))
                })
            },
        );
    }

    group.finish();
}

fn bench_weaver_chaff_injection(c: &mut Criterion) {
    let mut engine = WeaverEngine::new(WeaverProfile::default());
    let session = engine.generate_session(5.0);

    let mut group = c.benchmark_group("weaver_chaff_injection");

    for ratio in [0.05, 0.1, 0.2, 0.5] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:.0}%", ratio * 100.0)),
            &ratio,
            |b, &r| {
                b.iter(|| {
                    let mut eng = WeaverEngine::new(WeaverProfile::default());
                    eng.generate_chaff(black_box(&session), black_box(r))
                })
            },
        );
    }

    group.finish();
}

fn bench_session_stats(c: &mut Criterion) {
    let mut engine = WeaverEngine::new(WeaverProfile::default());
    let session = engine.generate_session(10.0);

    c.bench_function("session_stats_from_packets", |b| {
        b.iter(|| SessionStats::from_packets(black_box(&session)))
    });
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

criterion_group!(
    crypto_benches,
    bench_hkdf_derive,
    bench_key_rotation,
    bench_chacha20_encrypt,
    bench_chacha20_decrypt,
);

criterion_group!(
    frame_benches,
    bench_frame_encode,
    bench_frame_decode,
    bench_frame_encrypt_decrypt,
);

criterion_group!(
    weaver_benches,
    bench_weaver_generate_session,
    bench_weaver_chaff_injection,
    bench_session_stats,
);

criterion_main!(crypto_benches, frame_benches, weaver_benches);
