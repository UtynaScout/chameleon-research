# Architecture

## Overview
The platform has two execution tracks:
- Python simulator (`python-simulator/`) for fast iteration and metrics experiments.
- Rust core (`rust-core/`) for performance-oriented parity implementation.

## Modules
- `Generator`: creates synthetic packet series from profile distributions.
- `MetricsCalculator`: compares generated and reference distributions.
- `ReferenceExtractor`: converts lab PCAP files into JSON statistics.

## Data flow
1. `reference_stats.json` is produced from lab captures.
2. Python generator creates synthetic packet stream.
3. Metrics are computed and written to `chameleon_stats.json`.
4. Rust modules replicate core logic for parity testing.

## Safety boundary
Use only in controlled lab environments for detector evaluation and network research.
