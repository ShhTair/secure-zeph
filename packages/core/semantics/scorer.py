"""Layer 2 — Semantic Scorer (stub).

ABC + StubSemanticScorer. Future: embedding-based detection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class SemanticResult:
    score: float = 0.0
    skipped: bool = True
    latency_ms: float = 0.0


class SemanticScorer(ABC):
    @abstractmethod
    def score(self, text: str) -> SemanticResult: ...


class StubSemanticScorer(SemanticScorer):
    """Always returns 0.0 and skipped=True. Placeholder for future embedding scorer."""

    def score(self, text: str) -> SemanticResult:
        return SemanticResult(score=0.0, skipped=True, latency_ms=0.0)
