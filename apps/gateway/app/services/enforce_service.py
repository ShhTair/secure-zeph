"""EnforceService — evaluates tool calls against policy + alignment gate.

Extracts the enforce logic from the endpoint into a testable service.
"""

from __future__ import annotations

import uuid

from packages.core.alignment.gate import AlignmentAction, AlignmentContext, AlignmentGate
from packages.core.schemas.enforce_request import EnforceRequest, EnforceResponse
from packages.core.schemas.scan_request import Decision, TrustZone
from packages.core.toolfirewall.firewall import ToolFirewall


class EnforceService:
    """Evaluates a proposed tool call against firewall policy and alignment gate."""

    def __init__(
        self,
        tool_firewall: ToolFirewall | None = None,
        alignment_gate: AlignmentGate | None = None,
    ):
        self.firewall = tool_firewall or ToolFirewall()
        self.gate = alignment_gate or AlignmentGate()

    def evaluate(self, request: EnforceRequest) -> EnforceResponse:
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        trace_entries: list[dict] = []

        # Layer 4: Tool Firewall
        fw = self.firewall.evaluate(
            tool_call=request.draft_tool_call,
            trust_zone=request.trust_zone,
            source_tainted=request.trust_zone in (TrustZone.RETRIEVED, TrustZone.TOOL_OUTPUT),
        )
        trace_entries.append({
            "layer": "L4_tool_firewall",
            "allowed": fw.allowed,
            "reasons": fw.reasons,
            "canary_leaked": fw.canary_leaked,
            "exfil_detected": fw.exfil_detected,
        })

        # Layer 5: Alignment Gate
        ctx = AlignmentContext(
            user_intent=request.user_intent,
            proposed_tool=request.draft_tool_call.name,
            proposed_action_summary=str(request.draft_tool_call.arguments),
            risk_score=request.risk_score,
            trust_zone=request.trust_zone.value,
            labels=request.labels,
        )
        align = self.gate.check(ctx)
        trace_entries.append({
            "layer": "L5_alignment_gate",
            "aligned": align.aligned,
            "action": align.action.value,
            "replan_hint": align.replan_hint,
        })

        # Decision logic
        if not fw.allowed:
            decision = Decision.BLOCK
            reason = "; ".join(fw.reasons)
        elif align.action == AlignmentAction.DENY:
            decision = Decision.BLOCK
            reason = align.replan_hint or "Alignment gate denied"
        elif align.action == AlignmentAction.REQUIRE_APPROVAL or fw.require_approval:
            decision = Decision.REQUIRE_APPROVAL
            reason = align.approval_reason or "Approval required"
        else:
            decision = Decision.ALLOW
            reason = "OK"

        return EnforceResponse(
            request_id=request_id,
            tool_policy_decision=decision,
            reason=reason,
            require_approval=fw.require_approval or align.action == AlignmentAction.REQUIRE_APPROVAL,
            canary_leaked=fw.canary_leaked,
            exfil_detected=fw.exfil_detected,
            trace=trace_entries,
        )
