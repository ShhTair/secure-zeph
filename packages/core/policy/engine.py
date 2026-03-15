"""Policy Engine — ABC and local YAML-backed implementation."""

from __future__ import annotations

import fnmatch
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from packages.core.schemas.policy import PolicyDecision


@dataclass
class ToolPolicyContext:
    """Context for policy evaluation."""
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    chain_depth: int = 0
    risk_score: float = 0.0
    trust_zone: str = "USER"
    tainted: bool = False
    text_content: str = ""


class PolicyEngine(ABC):
    """Abstract base class for policy engines (OPA-compatible contract)."""

    @abstractmethod
    def evaluate(self, context: ToolPolicyContext) -> PolicyDecision:
        """Evaluate a tool call against loaded policies."""
        ...

    @abstractmethod
    def reload(self) -> None:
        """Reload policies from source."""
        ...


class LocalPolicyEngine(PolicyEngine):
    """YAML-backed policy engine — evaluates tool calls against local policy files."""

    def __init__(self, policies: dict[str, Any]):
        self._tools = policies.get("tools", {})
        self._exfil = policies.get("exfil", {})
        self._approval = policies.get("approval", {})
        self._trust = policies.get("trust", {})
        self._canary_patterns = self._exfil.get("canary_patterns", [])
        self._blocked_domains = self._exfil.get("blocked_domains", [])
        self._raw = policies

    def reload(self) -> None:
        pass  # In-memory, no-op; loader recreates engine

    def evaluate(self, context: ToolPolicyContext) -> PolicyDecision:
        # 1. Check blocked tools
        for blocked in self._tools.get("blocked_tools", []):
            if context.tool_name == blocked.get("name"):
                return PolicyDecision(
                    allowed=False,
                    rule_id=f"blocked_tool:{context.tool_name}",
                    reason=blocked.get("reason", "Tool is blocked by policy"),
                )

        # 2. Check if tool is in allowlist
        allowed_tool = None
        for tool in self._tools.get("allowed_tools", []):
            if tool.get("name") == context.tool_name:
                allowed_tool = tool
                break

        default_action = self._tools.get("default_action", "deny")

        if allowed_tool is None:
            if default_action == "deny":
                return PolicyDecision(
                    allowed=False,
                    rule_id="default_deny",
                    reason=f"Tool '{context.tool_name}' not in allowlist",
                )
            elif default_action == "require_approval":
                return PolicyDecision(
                    allowed=False,
                    rule_id="default_require_approval",
                    reason=f"Tool '{context.tool_name}' requires approval (not in allowlist)",
                    require_approval=True,
                )

        # 3. Check chain depth
        global_max = self._tools.get("global_limits", {}).get("max_chain_depth", 5)
        tool_max = allowed_tool.get("max_chain_depth", global_max) if allowed_tool else global_max
        if context.chain_depth > tool_max:
            return PolicyDecision(
                allowed=False,
                rule_id=f"chain_depth_exceeded:{context.tool_name}",
                reason=f"Chain depth {context.chain_depth} exceeds max {tool_max}",
            )

        # 4. Check argument constraints
        if allowed_tool and "arg_constraints" in allowed_tool:
            violation = self._check_arg_constraints(
                context.arguments, allowed_tool["arg_constraints"]
            )
            if violation:
                return PolicyDecision(
                    allowed=False,
                    rule_id=f"arg_constraint:{context.tool_name}",
                    reason=violation,
                )

        # 5. Canary leak check
        for canary in self._canary_patterns:
            if canary in context.text_content:
                return PolicyDecision(
                    allowed=False,
                    rule_id="canary_leak",
                    reason=f"Canary token detected in request content",
                )

        # 6. Exfil domain check
        for domain in self._blocked_domains:
            if domain in context.text_content:
                return PolicyDecision(
                    allowed=False,
                    rule_id=f"blocked_domain:{domain}",
                    reason=f"Blocked domain '{domain}' detected in content",
                )

        # 7. Approval gates
        approval_required = self._check_approval_gates(context)
        if approval_required:
            return PolicyDecision(
                allowed=False,
                rule_id=f"approval_required:{context.tool_name}",
                reason=approval_required,
                require_approval=True,
            )

        return PolicyDecision(
            allowed=True,
            rule_id="allowed",
            reason="Tool call permitted by policy",
        )

    def _check_arg_constraints(
        self, arguments: dict[str, Any], constraints: dict[str, Any]
    ) -> str | None:
        for arg_name, rules in constraints.items():
            value = arguments.get(arg_name)
            if value is None:
                continue
            str_val = str(value)
            max_len = rules.get("max_length")
            if max_len and len(str_val) > max_len:
                return f"Argument '{arg_name}' exceeds max length {max_len}"
            for pattern in rules.get("blocked_patterns", []):
                if re.search(pattern, str_val, re.IGNORECASE):
                    return f"Argument '{arg_name}' matches blocked pattern"
        return None

    def _check_approval_gates(self, context: ToolPolicyContext) -> str | None:
        # Risk-based
        thresholds = self._approval.get("risk_thresholds", {})
        always_block = thresholds.get("always_block_above", 0.9)
        if context.risk_score > always_block:
            return f"Risk score {context.risk_score} exceeds block threshold {always_block}"

        bypass = self._approval.get("bypass_tools", [])
        if context.tool_name in bypass:
            return None

        require_above = thresholds.get("require_approval_above", 0.6)
        if context.risk_score > require_above:
            return f"Risk score {context.risk_score} exceeds approval threshold {require_above}"

        # Pattern-based gates
        for gate in self._approval.get("require_approval", []):
            pattern = gate.get("tool_pattern", "")
            if fnmatch.fnmatch(context.tool_name, pattern):
                return gate.get("reason", f"Tool '{context.tool_name}' requires approval")

        return None
