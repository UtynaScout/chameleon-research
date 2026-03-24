# Project Roadmap

## Phase 1: Python simulator stabilization (2 weeks)
- Fix parser and generation edge-cases
- Add profile validation and metrics report
- Add basic auto-tuning loop for profile params
- Deliver reproducible run on sample dataset

## Phase 2: Rust core bootstrap (2 weeks)
- Implement frame model and tests
- Implement scheduler skeleton with async ticks
- Add parity tests against Python outputs

## Phase 3: Documentation and CI (1 week)
- Finalize architecture docs
- Add CI for Python + Rust checks
- Provide reproducible local workflow

## Success metrics
- D_KL(Size) below agreed target in lab dataset
- D_KL(IAT) below agreed target in lab dataset
- Stable simulator execution with deterministic seed
