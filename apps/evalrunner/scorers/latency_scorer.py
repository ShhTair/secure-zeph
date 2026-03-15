"""Latency Scorer — scan + enforce latency percentiles."""

from __future__ import annotations

import statistics

from packages.core.schemas.scenario import ScenarioResult


def score_latency(results: list[ScenarioResult]) -> dict[str, float]:
    """Calculate latency percentiles from defended results.

    Returns dict with p50, p95, p99 in milliseconds.
    """
    latencies = [r.latency_ms for r in results if r.latency_ms > 0]
    if not latencies:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0}

    latencies.sort()
    n = len(latencies)

    return {
        "p50": _percentile(latencies, 0.50),
        "p95": _percentile(latencies, 0.95),
        "p99": _percentile(latencies, 0.99),
        "mean": statistics.mean(latencies),
        "count": float(n),
    }


def _percentile(sorted_data: list[float], pct: float) -> float:
    """Calculate percentile from sorted list."""
    n = len(sorted_data)
    if n == 0:
        return 0.0
    idx = pct * (n - 1)
    lower = int(idx)
    upper = min(lower + 1, n - 1)
    frac = idx - lower
    return round(sorted_data[lower] * (1 - frac) + sorted_data[upper] * frac, 3)
