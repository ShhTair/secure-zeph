"""Core Pydantic schemas — Scan request/response."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TrustZone(str, Enum):
    SYSTEM = "SYSTEM"
    USER = "USER"
    RETRIEVED = "RETRIEVED"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    MODEL_DRAFT = "MODEL_DRAFT"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class SourceMetadata(BaseModel):
    source_id: str = ""
    source_zone: TrustZone = TrustZone.USER
    origin_url: str | None = None
    trust_level: float = 1.0


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    user_input: str
    retrieved_context: list[str] = Field(default_factory=list)
    source_metadata: list[SourceMetadata] = Field(default_factory=list)
    user_intent: str = ""
    tools: list[str] = Field(default_factory=list)
    draft_tool_call: ToolCall | None = None


class TraceEntry(BaseModel):
    layer: str
    latency_ms: float = 0.0
    score: float | None = None
    labels: list[str] = Field(default_factory=list)
    verdict: str = ""
    skipped: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    request_id: str
    risk_score: float = 0.0
    labels: list[str] = Field(default_factory=list)
    decision: Decision = Decision.ALLOW
    sanitized_context: list[str] = Field(default_factory=list)
    trace: list[TraceEntry] = Field(default_factory=list)
