"""Layer 4 — Tool Firewall.

Validates tool calls against policy. Fail-closed by default.
Checks: allowlist, arg validation, exfiltration URLs, canary leaks, taint, chain depth.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from packages.core.schemas.scan_request import ToolCall, TrustZone


@dataclass
class FirewallVerdict:
    allowed: bool = False
    reasons: list[str] = field(default_factory=list)
    require_approval: bool = False
    canary_leaked: bool = False
    exfil_detected: bool = False
    latency_ms: float = 0.0


# Suspicious URL patterns for exfiltration detection
_EXFIL_URL_RE = re.compile(
    r"https?://[^\s]+\?[^\s]*(?:data|secret|token|key|password|leaked|exfil|q)\s*=",
    re.IGNORECASE,
)


class ToolFirewall:
    """Evaluates a proposed tool call against security policies."""

    def __init__(
        self,
        allowed_tools: set[str] | None = None,
        blocked_tools: set[str] | None = None,
        canary_tokens: list[str] | None = None,
        max_chain_depth: int = 5,
    ):
        self.allowed_tools = allowed_tools or set()
        self.blocked_tools = blocked_tools or {"Terminal.Execute", "shell", "bash", "cmd"}
        self.canary_tokens = canary_tokens or []
        self.max_chain_depth = max_chain_depth

    def evaluate(
        self,
        tool_call: ToolCall,
        trust_zone: TrustZone = TrustZone.USER,
        chain_depth: int = 0,
        source_tainted: bool = False,
    ) -> FirewallVerdict:
        start = time.perf_counter()
        reasons: list[str] = []
        require_approval = False
        canary_leaked = False
        exfil_detected = False

        # 1. Blocked tools check
        if tool_call.name in self.blocked_tools:
            reasons.append(f"Tool '{tool_call.name}' is in blocked list")

        # 2. Allowlist check (if configured)
        if self.allowed_tools and tool_call.name not in self.allowed_tools:
            reasons.append(f"Tool '{tool_call.name}' not in allowlist")

        # 3. Chain depth limit
        if chain_depth >= self.max_chain_depth:
            reasons.append(f"Chain depth {chain_depth} exceeds max {self.max_chain_depth}")

        # 4. Taint check — untrusted source influencing tool call
        if source_tainted and trust_zone in (TrustZone.RETRIEVED, TrustZone.TOOL_OUTPUT):
            require_approval = True
            reasons.append("Source-tainted tool call from untrusted zone requires approval")

        # 5. Canary token leak detection
        arg_text = str(tool_call.arguments)
        for canary in self.canary_tokens:
            if canary and canary in arg_text:
                canary_leaked = True
                reasons.append(f"Canary token leaked in arguments")
                break

        # 6. Exfiltration URL detection in arguments
        if _EXFIL_URL_RE.search(arg_text):
            exfil_detected = True
            reasons.append("Potential exfiltration URL detected in arguments")

        allowed = len(reasons) == 0
        elapsed_ms = (time.perf_counter() - start) * 1000

        return FirewallVerdict(
            allowed=allowed,
            reasons=reasons,
            require_approval=require_approval,
            canary_leaked=canary_leaked,
            exfil_detected=exfil_detected,
            latency_ms=round(elapsed_ms, 3),
        )
