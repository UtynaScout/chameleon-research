from __future__ import annotations

import json
import logging
import random
from copy import deepcopy
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import numpy as np
from metrics_calculator import MetricsCalculator


logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
LOGGER = logging.getLogger("chameleon-simulator")

MIN_PKT_SIZE = 54
MAX_PKT_SIZE = 1500
DEFAULT_BINS = 12
IAT_BINS = 8


class TrafficState(str, Enum):
    IDLE = "IDLE"
    REQUEST = "REQUEST"
    STREAM = "STREAM"
    ACK = "ACK"


@dataclass(slots=True)
class Packet:
    timestamp: float
    size: int
    direction: str
    state: TrafficState


DEFAULT_TRANSITION_MATRIX: dict[TrafficState, dict[TrafficState, float]] = {
    TrafficState.IDLE: {TrafficState.IDLE: 0.25, TrafficState.REQUEST: 0.5, TrafficState.ACK: 0.25},
    TrafficState.REQUEST: {TrafficState.STREAM: 0.7, TrafficState.ACK: 0.2, TrafficState.IDLE: 0.1},
    TrafficState.STREAM: {TrafficState.STREAM: 0.65, TrafficState.ACK: 0.25, TrafficState.IDLE: 0.1},
    TrafficState.ACK: {TrafficState.REQUEST: 0.35, TrafficState.STREAM: 0.35, TrafficState.IDLE: 0.3},
}

DEFAULT_STATE_PROFILES: dict[TrafficState, dict[str, Any]] = {
    TrafficState.IDLE: {"iat_ms": [80, 120, 160, 220], "size_bytes": [60, 80, 100], "up_prob": 0.25},
    TrafficState.REQUEST: {"iat_ms": [8, 12, 20, 35], "size_bytes": [280, 420, 680, 920], "up_prob": 0.8},
    TrafficState.STREAM: {"iat_ms": [2, 4, 6, 10], "size_bytes": [900, 1200, 1350, 1450], "up_prob": 0.35},
    TrafficState.ACK: {"iat_ms": [4, 7, 11], "size_bytes": [54, 60, 66, 74], "up_prob": 0.5},
}


TARGET_REF_STATE_WEIGHTS: dict[TrafficState, float] = {
    TrafficState.IDLE: 0.17,
    TrafficState.REQUEST: 0.16,
    TrafficState.STREAM: 0.49,
    TrafficState.ACK: 0.18,
}


class MetaProfileGenerator:
    def __init__(
        self,
        transition_matrix: dict[TrafficState, dict[TrafficState, float]] | None = None,
        state_profiles: dict[TrafficState, dict[str, Any]] | None = None,
        seed: int = 42,
    ) -> None:
        self.transition_matrix = transition_matrix or DEFAULT_TRANSITION_MATRIX
        self.state_profiles = state_profiles or DEFAULT_STATE_PROFILES
        self.rng = random.Random(seed)
        np.random.seed(seed)
        self._validate_profiles()

    def _validate_profiles(self) -> None:
        for state, profile in self.state_profiles.items():
            if not profile.get("iat_ms") or not profile.get("size_bytes"):
                raise ValueError(f"Invalid profile for {state}: missing iat_ms/size_bytes")
            if not 0.0 <= float(profile.get("up_prob", 0.5)) <= 1.0:
                raise ValueError(f"Invalid up_prob for {state}")

            iat_values = [float(value) for value in profile["iat_ms"]]
            size_values = [int(value) for value in profile["size_bytes"]]
            if any(value <= 0 for value in iat_values):
                raise ValueError(f"Invalid iat_ms for {state}: all values must be > 0")
            if any(value < MIN_PKT_SIZE or value > MAX_PKT_SIZE for value in size_values):
                raise ValueError(
                    f"Invalid size_bytes for {state}: values must be in [{MIN_PKT_SIZE}, {MAX_PKT_SIZE}]"
                )

        for state, transitions in self.transition_matrix.items():
            total = sum(transitions.values())
            if not np.isclose(total, 1.0):
                raise ValueError(f"Transition probabilities for {state} must sum to 1.0, got {total}")

    def _next_state(self, current: TrafficState) -> TrafficState:
        states = list(self.transition_matrix[current].keys())
        probs = list(self.transition_matrix[current].values())
        return self.rng.choices(states, weights=probs, k=1)[0]

    def _sample_iat_ms(self, state: TrafficState) -> float:
        base = self.rng.choice(self.state_profiles[state]["iat_ms"])
        jitter = np.random.normal(loc=0.0, scale=max(0.05, base * 0.02))
        value = base + jitter
        return float(max(0.8, value))

    def _sample_size(self, state: TrafficState) -> int:
        base = self.rng.choice(self.state_profiles[state]["size_bytes"])
        noise = int(np.random.normal(loc=0.0, scale=max(0.5, base * 0.005)))
        return int(min(MAX_PKT_SIZE, max(MIN_PKT_SIZE, base + noise)))

    def generate(self, packet_count: int = 4000) -> list[Packet]:
        packets: list[Packet] = []
        ts = 0.0
        state = TrafficState.IDLE

        for _ in range(packet_count):
            iat_ms = self._sample_iat_ms(state)
            ts += iat_ms / 1000.0
            size = self._sample_size(state)
            up_prob = float(self.state_profiles[state]["up_prob"])
            direction = "up" if self.rng.random() < up_prob else "down"
            packets.append(Packet(timestamp=ts, size=size, direction=direction, state=state))
            state = self._next_state(state)

        return packets

    def state_distribution(self, packets: list[Packet]) -> dict[TrafficState, float]:
        counts = Counter(packet.state for packet in packets)
        total = max(len(packets), 1)
        return {state: counts.get(state, 0) / total for state in TrafficState}


def _validate_reference_profile(data: dict[str, Any]) -> list[str]:
    warnings: list[str] = []

    required_keys = ["packet_sizes", "iat_ms"]
    for key in required_keys:
        if key not in data:
            raise ValueError(f"Reference profile missing required key: {key}")

    if "iat_samples" not in data:
        warnings.append("Optional key 'iat_samples' is missing; using 'iat_ms'.")
    if "size_samples" not in data:
        warnings.append("Optional key 'size_samples' is missing; using 'packet_sizes'.")
    if "entropy_samples" not in data:
        warnings.append("Optional key 'entropy_samples' is missing; entropy diagnostics are skipped.")

    packet_sizes = data.get("packet_sizes", [])
    iat_values = data.get("iat_ms", [])
    if not isinstance(packet_sizes, list) or not isinstance(iat_values, list):
        raise ValueError("Reference profile fields packet_sizes and iat_ms must be lists")
    if len(packet_sizes) == 0 or len(iat_values) == 0:
        raise ValueError("Reference profile must include non-empty packet_sizes and iat_ms")

    if any((not isinstance(value, (int, float))) for value in packet_sizes):
        raise ValueError("packet_sizes must contain numeric values")
    if any((not isinstance(value, (int, float))) for value in iat_values):
        raise ValueError("iat_ms must contain numeric values")

    if any(float(value) <= 0 for value in iat_values):
        raise ValueError("iat_ms values must be > 0")
    if any(int(value) < MIN_PKT_SIZE or int(value) > MAX_PKT_SIZE for value in packet_sizes):
        warnings.append(f"Some packet_sizes are outside [{MIN_PKT_SIZE}, {MAX_PKT_SIZE}]")

    return warnings


def _load_reference(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Reference file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data


def _print_diagnostic_table(title: str, headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    border = "┌" + "┬".join("─" * (width + 2) for width in widths) + "┐"
    split = "├" + "┼".join("─" * (width + 2) for width in widths) + "┤"
    end = "└" + "┴".join("─" * (width + 2) for width in widths) + "┘"

    LOGGER.info(title)
    LOGGER.info(border)
    LOGGER.info("│ " + " │ ".join(headers[idx].ljust(widths[idx]) for idx in range(len(headers))) + " │")
    LOGGER.info(split)
    for row in rows:
        LOGGER.info("│ " + " │ ".join(row[idx].ljust(widths[idx]) for idx in range(len(row))) + " │")
    LOGGER.info(end)


def _stationary_distribution(
    transition_matrix: dict[TrafficState, dict[TrafficState, float]],
    iterations: int = 100,
) -> dict[TrafficState, float]:
    states = list(TrafficState)
    probs = np.full(len(states), 1.0 / len(states), dtype=float)
    matrix = np.zeros((len(states), len(states)), dtype=float)

    for row_idx, source in enumerate(states):
        for col_idx, target in enumerate(states):
            matrix[row_idx, col_idx] = transition_matrix[source].get(target, 0.0)

    for _ in range(iterations):
        probs = probs @ matrix

    return {states[idx]: float(probs[idx]) for idx in range(len(states))}


def _log_state_distribution(
    observed: dict[TrafficState, float],
    expected: dict[TrafficState, float],
) -> None:
    rows: list[list[str]] = []
    for state in TrafficState:
        exp_pct = expected.get(state, 0.0) * 100.0
        obs_pct = observed.get(state, 0.0) * 100.0
        delta = obs_pct - exp_pct
        marker = "⚠" if abs(delta) > 20.0 else ""
        rows.append([
            state.value,
            f"{exp_pct:.1f}%",
            f"{obs_pct:.1f}%",
            f"{delta:+.1f}% {marker}".strip(),
        ])

    _print_diagnostic_table(
        title="📊 STATE DISTRIBUTION LOG",
        headers=["State", "Expected (%)", "Observed (%)", "Delta"],
        rows=rows,
    )


def _build_size_profile_from_reference(reference_sizes: list[float]) -> dict[TrafficState, list[int]]:
    values = sorted(int(min(MAX_PKT_SIZE, max(MIN_PKT_SIZE, value))) for value in reference_sizes)
    low = [value for value in values if value <= 96]
    mid = [value for value in values if 96 < value <= 700]
    high = [value for value in values if value > 700]

    if len(low) == 0:
        low = [60, 66, 74]
    if len(mid) == 0:
        mid = [128, 256, 512]
    if len(high) == 0:
        high = [900, 1200, 1400]

    low = sorted(set(low))
    mid = sorted(set(mid))
    high = sorted(set(high))

    return {
        TrafficState.IDLE: low[: min(4, len(low))],
        TrafficState.REQUEST: mid[: min(4, len(mid))],
        TrafficState.STREAM: high[: min(4, len(high))],
        TrafficState.ACK: low[: min(4, len(low))],
    }


def _build_iat_profile_from_reference(reference_iat: list[float]) -> dict[TrafficState, list[float]]:
    values = sorted(float(value) for value in reference_iat)

    def pick(index: int) -> float:
        return values[min(max(index, 0), len(values) - 1)]

    low = [pick(0), pick(1), pick(2), pick(3)]
    mid = [pick(4), pick(5), pick(6), pick(7)]
    high = [pick(7), pick(8), pick(9), pick(10)]

    return {
        TrafficState.STREAM: [max(0.8, value) for value in low],
        TrafficState.REQUEST: [max(0.8, value) for value in mid],
        TrafficState.IDLE: [max(0.8, value) for value in high],
        TrafficState.ACK: [max(0.8, value) for value in [low[0], low[2], mid[0], mid[1]]],
    }


def random_search_optimization(
    reference: dict[str, Any],
    iterations: int = 50,
    seed: int = 123,
) -> tuple[
    dict[TrafficState, dict[str, Any]],
    dict[TrafficState, dict[TrafficState, float]],
    float,
    float,
]:
    safe_iterations = max(1, min(iterations, 50))
    rng = random.Random(seed)

    ref_sizes = [float(value) for value in reference["packet_sizes"]]
    ref_iat = [float(value) for value in reference["iat_ms"]]
    best_profile = deepcopy(DEFAULT_STATE_PROFILES)
    best_transition = deepcopy(DEFAULT_TRANSITION_MATRIX)
    best_score = float("inf")
    best_size_kl = float("inf")
    best_iat_kl = float("inf")

    size_guides = _build_size_profile_from_reference(ref_sizes)
    iat_guides = _build_iat_profile_from_reference(ref_iat)

    for _ in range(safe_iterations):
        candidate = deepcopy(DEFAULT_STATE_PROFILES)
        for state in TrafficState:
            size_base = size_guides[state]
            candidate[state]["size_bytes"] = [
                int(min(MAX_PKT_SIZE, max(MIN_PKT_SIZE, value + rng.randint(-8, 8)))) for value in size_base
            ]

            iat_base = iat_guides[state]

            candidate[state]["iat_ms"] = [
                max(0.8, value * rng.uniform(0.98, 1.02)) for value in iat_base
            ]
            candidate[state]["up_prob"] = float(min(0.95, max(0.05, candidate[state]["up_prob"] + rng.uniform(-0.08, 0.08))))

        stream_target = TARGET_REF_STATE_WEIGHTS[TrafficState.STREAM]
        idle_target = TARGET_REF_STATE_WEIGHTS[TrafficState.IDLE]
        candidate_transition = deepcopy(DEFAULT_TRANSITION_MATRIX)
        candidate_transition[TrafficState.REQUEST][TrafficState.STREAM] = min(0.9, max(0.5, stream_target + rng.uniform(-0.06, 0.08)))
        candidate_transition[TrafficState.REQUEST][TrafficState.ACK] = min(0.3, max(0.05, 1.0 - candidate_transition[TrafficState.REQUEST][TrafficState.STREAM] - 0.1))
        candidate_transition[TrafficState.REQUEST][TrafficState.IDLE] = 1.0 - candidate_transition[TrafficState.REQUEST][TrafficState.STREAM] - candidate_transition[TrafficState.REQUEST][TrafficState.ACK]

        candidate_transition[TrafficState.STREAM][TrafficState.STREAM] = min(0.85, max(0.45, stream_target + rng.uniform(-0.05, 0.05)))
        candidate_transition[TrafficState.STREAM][TrafficState.ACK] = min(0.35, max(0.1, 1.0 - candidate_transition[TrafficState.STREAM][TrafficState.STREAM] - idle_target))
        candidate_transition[TrafficState.STREAM][TrafficState.IDLE] = 1.0 - candidate_transition[TrafficState.STREAM][TrafficState.STREAM] - candidate_transition[TrafficState.STREAM][TrafficState.ACK]

        generator = MetaProfileGenerator(
            transition_matrix=candidate_transition,
            state_profiles=candidate,
            seed=rng.randint(1, 10_000),
        )
        packets = generator.generate(packet_count=2500)
        gen_sizes = [packet.size for packet in packets]
        gen_iat = _iat_series([packet.timestamp for packet in packets])

        size_metrics = MetricsCalculator.compare_distributions(ref_sizes, gen_sizes, bins=DEFAULT_BINS)
        iat_metrics = MetricsCalculator.compare_distributions(ref_iat, gen_iat, bins=IAT_BINS)
        score = size_metrics.d_kl * 0.55 + iat_metrics.d_kl * 0.45

        if score < best_score:
            best_score = score
            best_profile = candidate
            best_transition = candidate_transition
            best_size_kl = size_metrics.d_kl
            best_iat_kl = iat_metrics.d_kl

    return best_profile, best_transition, best_size_kl, best_iat_kl


def _iat_series(timestamps: list[float]) -> list[float]:
    if len(timestamps) < 2:
        return []
    values = np.diff(np.asarray(timestamps, dtype=float)) * 1000.0
    return values.tolist()


def run() -> None:
    root = Path(__file__).resolve().parents[1]
    ref_path = root / "data" / "reference_stats.json"

    LOGGER.info("Loading reference stats from %s", ref_path)
    reference = _load_reference(ref_path)
    warnings = _validate_reference_profile(reference)
    for warning in warnings:
        LOGGER.warning("Reference validation: %s", warning)

    LOGGER.info("Running safe random search optimization on synthetic laboratory profile")
    tuned_profile, tuned_transition, pre_size_kl, pre_iat_kl = random_search_optimization(
        reference=reference,
        iterations=50,
        seed=123,
    )
    LOGGER.info("Best candidate from random search: D_KL(Size)=%.4f | D_KL(IAT)=%.4f", pre_size_kl, pre_iat_kl)

    generator = MetaProfileGenerator(
        transition_matrix=tuned_transition,
        state_profiles=tuned_profile,
        seed=123,
    )
    packets = generator.generate(packet_count=4000)

    gen_sizes = [p.size for p in packets]
    gen_iat = _iat_series([p.timestamp for p in packets])
    gen_up_ratio = sum(1 for p in packets if p.direction == "up") / max(len(packets), 1)

    ref_sizes = reference.get("packet_sizes", [])
    ref_iat = reference.get("iat_ms", [])
    ref_up_ratio = float(reference.get("up_ratio", 0.5))

    size_metrics = MetricsCalculator.compare_distributions(ref_sizes, gen_sizes, bins=DEFAULT_BINS)
    iat_metrics = MetricsCalculator.compare_distributions(ref_iat, gen_iat, bins=IAT_BINS)
    ratio_diff = MetricsCalculator.ratio_diff(ref_up_ratio, gen_up_ratio)

    expected_distribution = _stationary_distribution(generator.transition_matrix)
    observed_distribution = generator.state_distribution(packets)
    _log_state_distribution(observed=observed_distribution, expected=expected_distribution)

    size_diag = MetricsCalculator.diagnostic_report(
        metric_name="Size",
        reference=ref_sizes,
        generated=gen_sizes,
        bins=DEFAULT_BINS,
        top_n=5,
    )
    iat_diag = MetricsCalculator.diagnostic_report(
        metric_name="IAT",
        reference=ref_iat,
        generated=gen_iat,
        bins=IAT_BINS,
        top_n=5,
    )

    _print_diagnostic_table(
        title="🔍 DIAGNOSTIC REPORT — Top 5 Divergence Bins (Size)",
        headers=["Range", "Ref (%)", "Gen (%)", "KL contrib"],
        rows=[
            [
                f"{row.left:.1f}-{row.right:.1f}",
                f"{row.ref_prob * 100.0:.2f}",
                f"{row.gen_prob * 100.0:.2f}",
                f"{row.kl_contrib:+.4f}",
            ]
            for row in size_diag.bins
        ],
    )
    _print_diagnostic_table(
        title="🔍 DIAGNOSTIC REPORT — Top 5 Divergence Bins (IAT)",
        headers=["Range", "Ref (%)", "Gen (%)", "KL contrib"],
        rows=[
            [
                f"{row.left:.2f}-{row.right:.2f}",
                f"{row.ref_prob * 100.0:.2f}",
                f"{row.gen_prob * 100.0:.2f}",
                f"{row.kl_contrib:+.4f}",
            ]
            for row in iat_diag.bins
        ],
    )

    LOGGER.info("D_KL(Size)=%.4f | JS(Size)=%.4f | W(Size)=%.4f", size_metrics.d_kl, size_metrics.d_js, size_metrics.d_wasserstein)
    LOGGER.info("D_KL(IAT)=%.4f | JS(IAT)=%.4f | W(IAT)=%.4f", iat_metrics.d_kl, iat_metrics.d_js, iat_metrics.d_wasserstein)
    LOGGER.info("Up ratio diff=%.4f", ratio_diff)

    out = {
        "packet_sizes": gen_sizes,
        "iat_ms": gen_iat,
        "up_ratio": gen_up_ratio,
        "packet_count": len(packets),
    }
    out_path = root / "data" / "chameleon_stats.json"
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    LOGGER.info("Saved generated stats to %s", out_path)


if __name__ == "__main__":
    run()
