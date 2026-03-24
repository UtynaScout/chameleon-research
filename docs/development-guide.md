# Development Guide

## Python
- Create and activate venv.
- Install requirements from `python-simulator/requirements.txt`.
- Run simulator:
  - `python python-simulator/meta_profile_generator_v2.py`

## Rust
- Build core:
  - `cd rust-core`
  - `cargo build`
- Run tests:
  - `cargo test`

## Recommended workflow
1. Update profile parameters in Python.
2. Validate metrics against `data/reference_stats.json`.
3. Port stable logic to Rust and run parity checks.

## v0.3.1 (2026-03-24)
- Added histogram diagnostic report with top divergence bins for Size and IAT.
- Added state distribution logging with expected vs observed percentages.
- Added reference profile validation and warning flow for optional fields.
- Added safe random-search tuning (max 50 iterations) for synthetic lab profiles.
- Improved generator robustness with packet size clamping and stricter profile checks.
