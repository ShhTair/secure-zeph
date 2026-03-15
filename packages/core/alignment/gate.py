"""Layer 5 — Alignment Gate.

Verifies proposed action serves the user's stated intent.
Gate NEVER sees raw retrieved_context — only structured metadata.
Design ref: Google User Alignment Critic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class AlignmentAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REPLAN = "REPLAN"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass
class AlignmentContext:
    user_intent: str = ""
    proposed_tool: str = ""
    proposed_action_summary: str = ""
    risk_score: float = 0.0
    trust_zone: str = "USER"
    labels: list[str] = field(default_factory=list)


@dataclass
class AlignmentVerdict:
    aligned: bool = True
    confidence: float = 1.0
    action: AlignmentAction = AlignmentAction.ALLOW
    replan_hint: str = ""
    approval_reason: str = ""
    latency_ms: float = 0.0


# Tools that always bypass alignment check
_BYPASS_TOOLS = frozenset(["calculator", "search", "read_file", "get_weather"])

# Tools that always require mandatory alignment check
_MANDATORY_TOOLS = frozenset([
    "send_email", "file_write", "file_delete", "api_call_external",
    "Terminal.Execute", "shell", "transfer_funds", "grant_access",
])

# Obvious mismatch patterns: (intent_keyword, tool_name) → deny
_MISMATCH_MAP: dict[str, set[str]] = {
    "search": {"send_email", "file_delete", "Terminal.Execute", "transfer_funds"},
    "read": {"send_email", "file_delete", "Terminal.Execute", "transfer_funds"},
    "calculate": {"send_email", "file_delete", "Terminal.Execute"},
    "weather": {"send_email", "file_delete", "Terminal.Execute", "transfer_funds"},
}


class AlignmentGate:
    """Rule-based alignment check between user intent and proposed action."""

    def __init__(
        self,
        bypass_tools: frozenset[str] | None = None,
        mandatory_tools: frozenset[str] | None = None,
    ):
        self.bypass_tools = bypass_tools or _BYPASS_TOOLS
        self.mandatory_tools = mandatory_tools or _MANDATORY_TOOLS

    def check(self, context: AlignmentContext) -> AlignmentVerdict:
        start = time.perf_counter()

        tool = context.proposed_tool

        # Bypass for safe tools
        if tool in self.bypass_tools:
            elapsed = (time.perf_counter() - start) * 1000
            return AlignmentVerdict(aligned=True, confidence=1.0, latency_ms=round(elapsed, 3))

        # High risk score → require approval
        if context.risk_score >= 0.8:
            elapsed = (time.perf_counter() - start) * 1000
            return AlignmentVerdict(
                aligned=False,
                confidence=0.3,
                action=AlignmentAction.REQUIRE_APPROVAL,
                approval_reason=f"High risk score ({context.risk_score:.2f}) for tool '{tool}'",
                latency_ms=round(elapsed, 3),
            )

        # Mandatory tools from untrusted zones → require approval
        if tool in self.mandatory_tools and context.trust_zone in ("RETRIEVED", "TOOL_OUTPUT"):
            elapsed = (time.perf_counter() - start) * 1000
            return AlignmentVerdict(
                aligned=False,
                confidence=0.4,
                action=AlignmentAction.REQUIRE_APPROVAL,
                approval_reason=f"Mandatory tool '{tool}' triggered from untrusted zone",
                latency_ms=round(elapsed, 3),
            )

        # Obvious mismatch detection
        intent_lower = context.user_intent.lower()
        for intent_kw, blocked_tools in _MISMATCH_MAP.items():
            if intent_kw in intent_lower and tool in blocked_tools:
                elapsed = (time.perf_counter() - start) * 1000
                return AlignmentVerdict(
                    aligned=False,
                    confidence=0.2,
                    action=AlignmentAction.DENY,
                    replan_hint=f"User intent '{intent_kw}' doesn't match tool '{tool}'",
                    latency_ms=round(elapsed, 3),
                )

        # Default: allow with moderate confidence
        elapsed = (time.perf_counter() - start) * 1000
        return AlignmentVerdict(
            aligned=True,
            confidence=0.7,
            action=AlignmentAction.ALLOW,
            latency_ms=round(elapsed, 3),
        )
