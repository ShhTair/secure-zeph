"""Core Pydantic schemas — Policy models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from packages.core.schemas.scan_request import Decision


class PolicyRule(BaseModel):
    id: str
    type: str  # "tool_allowlist" | "arg_constraint" | "exfil_control" | "approval_gate"
    target: str = ""  # tool name or pattern
    constraints: dict[str, Any] = Field(default_factory=dict)
    action: Decision = Decision.BLOCK
    description: str = ""


class PolicyDecision(BaseModel):
    allowed: bool = True
    rule_id: str = ""
    reason: str = ""
    require_approval: bool = False
