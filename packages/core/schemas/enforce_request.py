"""Core Pydantic schemas — Enforce request/response."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from packages.core.schemas.scan_request import Decision, ToolCall, TrustZone


class EnforceRequest(BaseModel):
    draft_tool_call: ToolCall
    tool_schema: dict[str, Any] = Field(default_factory=dict)
    source_influence_map: dict[str, float] = Field(default_factory=dict)
    user_intent: str = ""
    risk_score: float = 0.0
    labels: list[str] = Field(default_factory=list)
    trust_zone: TrustZone = TrustZone.USER


class EnforceResponse(BaseModel):
    request_id: str
    tool_policy_decision: Decision = Decision.ALLOW
    reason: str = ""
    require_approval: bool = False
    approval_id: str | None = None
    canary_leaked: bool = False
    exfil_detected: bool = False
    trace: list[dict[str, Any]] = Field(default_factory=list)
