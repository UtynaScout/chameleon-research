# Phase 2 Checklist (Rust Core)

## Toolchain prerequisites
- [ ] Visual Studio Build Tools installed
- [ ] `rustc --version` works
- [ ] `cargo --version` works
- [ ] `cargo test` runs in `rust-core/`

## Code parity goals
- [ ] Match frame model semantics with Python generator outputs
- [ ] Implement deterministic packet generation path for parity tests
- [ ] Add integration fixtures from `data/baseline_v0.3.1.json`

## Quality gates
- [ ] All Rust unit tests pass
- [ ] Basic parity metrics script completes without errors
- [ ] Update docs with benchmark results and known limitations

## Safety constraints
- [ ] Keep scope on synthetic lab benchmarking only
- [ ] Do not add stealth/evasion features
- [ ] Preserve transparent logging and testability
