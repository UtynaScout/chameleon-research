# Chameleon Research

## ⚠️ Этическое Использование

Этот проект предназначен исключительно для:
- Научных исследований в области сетевого анализа
- Тестирования систем мониторинга и классификации трафика
- Образовательных целей

Запрещено использование для обхода систем безопасности без разрешения.

Research platform for synthetic network traffic generation and statistical analysis in a controlled lab setting.

## Scope
- Synthetic traffic generation for testing and benchmarking detectors
- Distribution matching and quality metrics (KL, JS, Wasserstein)
- Python-first experimentation with planned Rust parity modules

## Safety boundaries
This project is for defensive research and education only.
It does not include functionality for censorship circumvention, stealth communication, or evasion guidance.

## Quick start
### Python simulator
1. Create venv:
   - `python -m venv .venv`
   - `.venv\\Scripts\\Activate.ps1`
2. Install deps:
   - `pip install -r python-simulator/requirements.txt`
3. Run:
   - `python python-simulator/meta_profile_generator_v2.py`

### Rust core
1. `cd rust-core`
2. `cargo build`
3. `cargo test`

## Project layout
See `PROJECT_ROADMAP.md` and `docs/development-guide.md`.
