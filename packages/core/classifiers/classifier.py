"""Layer 3 — Classifier (mock). 🔒 D-10

ABC + MockClassifier. Future: DeBERTa, DistilBERT, OpenAI Guardrails API.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ClassifierResult:
    label: str = "BENIGN"  # "BENIGN" | "INJECTION" | "UNKNOWN"
    confidence: float = 0.5
    skipped: bool = True
    latency_ms: float = 0.0


class Classifier(ABC):
    @abstractmethod
    def classify(self, text: str) -> ClassifierResult: ...


class MockClassifier(Classifier):
    """Returns BENIGN with 0.5 confidence. 🔒 D-10: mock only for v1."""

    def classify(self, text: str) -> ClassifierResult:
        return ClassifierResult(label="BENIGN", confidence=0.5, skipped=True, latency_ms=0.0)
