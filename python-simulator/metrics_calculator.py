from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
from scipy.spatial.distance import jensenshannon
from scipy.stats import wasserstein_distance


EPS = 1e-12


@dataclass(slots=True)
class MetricResult:
    d_kl: float
    d_js: float
    d_wasserstein: float


@dataclass(slots=True)
class BinDiagnostic:
    left: float
    right: float
    ref_prob: float
    gen_prob: float
    kl_contrib: float


@dataclass(slots=True)
class DiagnosticResult:
    metric_name: str
    bins: list[BinDiagnostic]


class MetricsCalculator:
    @staticmethod
    def _to_prob(hist: np.ndarray) -> np.ndarray:
        arr = np.asarray(hist, dtype=float)
        arr = np.clip(arr, EPS, None)
        return arr / np.sum(arr)

    @staticmethod
    def kl_divergence(p: np.ndarray, q: np.ndarray) -> float:
        p_ = MetricsCalculator._to_prob(p)
        q_ = MetricsCalculator._to_prob(q)
        return float(np.sum(p_ * np.log(p_ / q_)))

    @staticmethod
    def compare_distributions(
        reference: Sequence[float],
        generated: Sequence[float],
        bins: int = 50,
    ) -> MetricResult:
        if len(reference) == 0 or len(generated) == 0:
            raise ValueError("Reference and generated arrays must be non-empty")

        low = min(min(reference), min(generated))
        high = max(max(reference), max(generated))

        if low == high:
            return MetricResult(d_kl=0.0, d_js=0.0, d_wasserstein=0.0)

        ref_hist, edges = np.histogram(reference, bins=bins, range=(low, high), density=False)
        gen_hist, _ = np.histogram(generated, bins=edges, density=False)

        d_kl = MetricsCalculator.kl_divergence(ref_hist, gen_hist)
        d_js = float(jensenshannon(MetricsCalculator._to_prob(ref_hist), MetricsCalculator._to_prob(gen_hist)))
        d_w = float(wasserstein_distance(reference, generated))
        return MetricResult(d_kl=d_kl, d_js=d_js, d_wasserstein=d_w)

    @staticmethod
    def ratio_diff(reference_ratio: float, generated_ratio: float) -> float:
        return abs(reference_ratio - generated_ratio)

    @staticmethod
    def diagnostic_report(
        metric_name: str,
        reference: Sequence[float],
        generated: Sequence[float],
        bins: int = 50,
        top_n: int = 5,
    ) -> DiagnosticResult:
        if len(reference) == 0 or len(generated) == 0:
            raise ValueError("Reference and generated arrays must be non-empty")

        low = min(min(reference), min(generated))
        high = max(max(reference), max(generated))

        if low == high:
            single = BinDiagnostic(
                left=float(low),
                right=float(high),
                ref_prob=1.0,
                gen_prob=1.0,
                kl_contrib=0.0,
            )
            return DiagnosticResult(metric_name=metric_name, bins=[single])

        ref_hist, edges = np.histogram(reference, bins=bins, range=(low, high), density=False)
        gen_hist, _ = np.histogram(generated, bins=edges, density=False)

        ref_prob = MetricsCalculator._to_prob(ref_hist)
        gen_prob = MetricsCalculator._to_prob(gen_hist)
        kl_contrib = ref_prob * np.log(ref_prob / gen_prob)

        diagnostics: list[BinDiagnostic] = []
        for idx in range(len(edges) - 1):
            diagnostics.append(
                BinDiagnostic(
                    left=float(edges[idx]),
                    right=float(edges[idx + 1]),
                    ref_prob=float(ref_prob[idx]),
                    gen_prob=float(gen_prob[idx]),
                    kl_contrib=float(kl_contrib[idx]),
                )
            )

        top_bins = sorted(diagnostics, key=lambda row: row.kl_contrib, reverse=True)[: max(1, top_n)]
        return DiagnosticResult(metric_name=metric_name, bins=top_bins)
