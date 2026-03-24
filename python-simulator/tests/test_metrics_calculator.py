from pathlib import Path
import sys

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from metrics_calculator import MetricsCalculator


def test_compare_distributions_identical():
    data = [1, 2, 2, 3, 5, 8]
    result = MetricsCalculator.compare_distributions(data, data, bins=5)
    assert result.d_kl < 1e-9
    assert result.d_js < 1e-9


def test_ratio_diff():
    assert MetricsCalculator.ratio_diff(0.5, 0.45) == pytest.approx(0.05)


def test_diagnostic_report_top_bins_count():
    reference = [64, 64, 72, 90, 128, 256, 512, 1024]
    generated = [64, 64, 64, 80, 96, 120, 160, 220]

    report = MetricsCalculator.diagnostic_report(
        metric_name="Size",
        reference=reference,
        generated=generated,
        bins=6,
        top_n=3,
    )

    assert report.metric_name == "Size"
    assert len(report.bins) == 3
    assert all(bin_row.right >= bin_row.left for bin_row in report.bins)


def test_diagnostic_report_empty_input_raises():
    with pytest.raises(ValueError):
        MetricsCalculator.diagnostic_report(
            metric_name="IAT",
            reference=[],
            generated=[1.0, 2.0],
        )
