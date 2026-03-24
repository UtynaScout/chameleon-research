# Metrics Guide

## Primary metrics
- `D_KL`: Kullback-Leibler divergence between histogram-based distributions.
- `D_JS`: Jensen-Shannon distance for symmetric comparison.
- `Wasserstein`: Earth mover distance in original value space.

## Secondary metrics
- `Up ratio diff`: absolute difference between reference and generated upload ratio.

## Notes
- Always compare on same histogram bins.
- Use fixed random seed for reproducibility.
- Track metrics per run in CI artifacts or local logs.
