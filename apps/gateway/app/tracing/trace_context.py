"""TraceContext — request-scoped tracing container.

Collects per-layer latencies, scores, labels, and verdicts across
the entire scan pipeline. Thread-safe via contextvars.
"""

from __future__ import annotations

import contextvars
import time
import uuid
from dataclasses import dataclass, field

_current_trace: contextvars.ContextVar[TraceContext | None] = contextvars.ContextVar(
    "current_trace", default=None
)


@dataclass
class LayerSpan:
    """A single layer execution span."""
    layer: str
    start_ns: int = 0
    end_ns: int = 0
    score: float | None = None
    labels: list[str] = field(default_factory=list)
    verdict: str = ""
    skipped: bool = False
    details: dict = field(default_factory=dict)

    @property
    def latency_ms(self) -> float:
        if self.end_ns and self.start_ns:
            return (self.end_ns - self.start_ns) / 1_000_000
        return 0.0


@dataclass
class TraceContext:
    """Request-scoped trace that accumulates layer spans."""
    request_id: str = field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    start_ns: int = field(default_factory=time.perf_counter_ns)
    spans: list[LayerSpan] = field(default_factory=list)
    _active_span: LayerSpan | None = field(default=None, repr=False)

    # --- Context manager for the overall request ---

    def __enter__(self) -> TraceContext:
        _current_trace.set(self)
        return self

    def __exit__(self, *exc) -> None:
        _current_trace.set(None)

    # --- Span management ---

    def start_span(self, layer: str) -> LayerSpan:
        """Begin timing a new layer."""
        span = LayerSpan(layer=layer, start_ns=time.perf_counter_ns())
        self._active_span = span
        return span

    def end_span(
        self,
        span: LayerSpan,
        *,
        score: float | None = None,
        labels: list[str] | None = None,
        verdict: str = "",
        skipped: bool = False,
        details: dict | None = None,
    ) -> None:
        """Finish a layer span and record it."""
        span.end_ns = time.perf_counter_ns()
        if score is not None:
            span.score = score
        if labels:
            span.labels = labels
        span.verdict = verdict
        span.skipped = skipped
        if details:
            span.details = details
        self.spans.append(span)
        if self._active_span is span:
            self._active_span = None

    # --- Convenience: layer context manager ---

    class _SpanCtx:
        def __init__(self, trace: TraceContext, layer: str):
            self._trace = trace
            self._span = trace.start_span(layer)

        def __enter__(self) -> LayerSpan:
            return self._span

        def __exit__(self, *exc) -> None:
            if self._span.end_ns == 0:
                self._span.end_ns = time.perf_counter_ns()
            if self._span not in self._trace.spans:
                self._trace.spans.append(self._span)

    def layer(self, name: str) -> _SpanCtx:
        """Usage: `with trace.layer('L0_normalization') as span: ...`"""
        return self._SpanCtx(self, name)

    # --- Export ---

    @property
    def total_latency_ms(self) -> float:
        return (time.perf_counter_ns() - self.start_ns) / 1_000_000

    def to_trace_entries(self) -> list[dict]:
        """Convert spans to serializable dicts (compatible with TraceEntry schema)."""
        return [
            {
                "layer": s.layer,
                "latency_ms": round(s.latency_ms, 3),
                "score": s.score,
                "labels": s.labels,
                "verdict": s.verdict,
                "skipped": s.skipped,
                "details": s.details,
            }
            for s in self.spans
        ]


def get_current_trace() -> TraceContext | None:
    """Get the active request trace from context."""
    return _current_trace.get()
