"""Core Pydantic schemas — Trace models."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


class RequestTrace(BaseModel):
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    timestamp: str = ""
    layer_traces: list[dict[str, Any]] = Field(default_factory=list)
    total_scan_latency_ms: float = 0.0
    risk_score: float = 0.0
    decision: str = ""
    policy_rule_id: str = ""
