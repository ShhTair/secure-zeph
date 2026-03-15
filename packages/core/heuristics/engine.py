"""Layer 1 — Heuristic Engine.

Fast pattern-based scanning using pre-compiled regex rules.
Target latency: < 5ms.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from packages.core.heuristics.rules import ALL_RULES, HeuristicRule


@dataclass
class HeuristicResult:
    score: float = 0.0
    labels: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    latency_ms: float = 0.0


class HeuristicEngine:
    """Scans normalized text against all heuristic rules."""

    def __init__(self, rules: list[HeuristicRule] | None = None, threshold: float = 0.0):
        self.rules = rules or ALL_RULES
        self.threshold = threshold

    def scan(self, text: str) -> HeuristicResult:
        start = time.perf_counter()

        matched: list[HeuristicRule] = []
        for rule in self.rules:
            if rule.match(text):
                matched.append(rule)

        score = min(1.0, sum(r.weight for r in matched))
        labels = sorted(set(r.label for r in matched))
        ids = [r.id for r in matched]

        elapsed_ms = (time.perf_counter() - start) * 1000

        return HeuristicResult(
            score=score,
            labels=labels,
            matched_rules=ids,
            latency_ms=round(elapsed_ms, 3),
        )
