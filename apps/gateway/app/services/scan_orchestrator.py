"""Scan Orchestrator — 6-layer defense pipeline.

L0: Normalization → L1: Heuristics → L2: Semantic → L3: Classifier
→ L4: Tool Firewall → L5: Alignment Gate

Conditional execution: L2/L3 only if L1 score > threshold.
L4/L5 only if tool_call is proposed.
"""

from __future__ import annotations

import time
import uuid

from packages.core.alignment.gate import AlignmentContext, AlignmentGate
from packages.core.classifiers.classifier import Classifier, MockClassifier
from packages.core.heuristics.engine import HeuristicEngine
from packages.core.normalization.normalizer import normalize_text
from packages.core.schemas.scan_request import (
    Decision,
    ScanRequest,
    ScanResponse,
    TraceEntry,
    TrustZone,
)
from packages.core.semantics.scorer import SemanticScorer, StubSemanticScorer
from packages.core.toolfirewall.firewall import ToolFirewall


class ScanOrchestrator:
    """Orchestrates the full 6-layer defense pipeline."""

    def __init__(
        self,
        heuristic_engine: HeuristicEngine | None = None,
        semantic_scorer: SemanticScorer | None = None,
        classifier: Classifier | None = None,
        tool_firewall: ToolFirewall | None = None,
        alignment_gate: AlignmentGate | None = None,
        l1_threshold: float = 0.3,
        block_threshold: float = 0.7,
        warn_threshold: float = 0.4,
    ):
        self.heuristic_engine = heuristic_engine or HeuristicEngine()
        self.semantic_scorer = semantic_scorer or StubSemanticScorer()
        self.classifier = classifier or MockClassifier()
        self.tool_firewall = tool_firewall or ToolFirewall()
        self.alignment_gate = alignment_gate or AlignmentGate()
        self.l1_threshold = l1_threshold
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold

    def scan(self, request: ScanRequest) -> ScanResponse:
        start = time.perf_counter()
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        trace: list[TraceEntry] = []
        all_labels: list[str] = []
        risk_score = 0.0

        # Combine texts for scanning
        texts_to_scan = [request.user_input] + request.retrieved_context

        for idx, text in enumerate(texts_to_scan):
            # --- Layer 0: Normalization ---
            l0_start = time.perf_counter()
            normalized, norm_flags = normalize_text(text)
            l0_ms = (time.perf_counter() - l0_start) * 1000

            norm_details = {
                k: v for k, v in norm_flags.__dict__.items()
                if v and v is not False and (not isinstance(v, list) or len(v) > 0)
            }
            trace.append(TraceEntry(
                layer="L0_normalization",
                latency_ms=round(l0_ms, 3),
                details={"text_index": idx, **norm_details},
            ))

            # --- Layer 1: Heuristics ---
            h_result = self.heuristic_engine.scan(normalized)
            trace.append(TraceEntry(
                layer="L1_heuristics",
                latency_ms=h_result.latency_ms,
                score=h_result.score,
                labels=h_result.labels,
                details={"matched_rules": h_result.matched_rules, "text_index": idx},
            ))
            risk_score = max(risk_score, h_result.score)
            all_labels.extend(h_result.labels)

            # L1 extra pass: scan decoded segments (base64, URL-decoded, zw-spaced)
            for seg in norm_flags.segments_decoded:
                _prefix, _, seg_text = seg.partition(":")
                if seg_text:
                    seg_result = self.heuristic_engine.scan(seg_text)
                    if seg_result.score > h_result.score:
                        risk_score = max(risk_score, seg_result.score)
                        all_labels.extend(seg_result.labels)

            # --- Layer 2: Semantic (conditional) ---
            if h_result.score >= self.l1_threshold:
                s_result = self.semantic_scorer.score(normalized)
                trace.append(TraceEntry(
                    layer="L2_semantic",
                    latency_ms=s_result.latency_ms,
                    score=s_result.score,
                    skipped=s_result.skipped,
                    details={"text_index": idx},
                ))
                if not s_result.skipped:
                    risk_score = max(risk_score, s_result.score)
            else:
                trace.append(TraceEntry(
                    layer="L2_semantic", skipped=True,
                    details={"reason": "L1 below threshold", "text_index": idx},
                ))

            # --- Layer 3: Classifier (conditional) ---
            if h_result.score >= self.l1_threshold:
                c_result = self.classifier.classify(normalized)
                trace.append(TraceEntry(
                    layer="L3_classifier",
                    latency_ms=c_result.latency_ms,
                    score=c_result.confidence,
                    labels=[c_result.label],
                    skipped=c_result.skipped,
                    details={"text_index": idx},
                ))
                if c_result.label == "INJECTION" and not c_result.skipped:
                    risk_score = max(risk_score, c_result.confidence)
                    all_labels.append("CLASSIFIER_INJECTION")
            else:
                trace.append(TraceEntry(
                    layer="L3_classifier", skipped=True,
                    details={"reason": "L1 below threshold", "text_index": idx},
                ))

        # --- Layer 4 & 5: Tool Firewall + Alignment Gate (if tool call proposed) ---
        if request.draft_tool_call:
            # Determine trust zone
            trust_zone = TrustZone.USER
            if request.source_metadata:
                trust_zone = request.source_metadata[0].source_zone

            # L4: Tool Firewall
            fw_verdict = self.tool_firewall.evaluate(
                tool_call=request.draft_tool_call,
                trust_zone=trust_zone,
                source_tainted=trust_zone in (TrustZone.RETRIEVED, TrustZone.TOOL_OUTPUT),
            )
            trace.append(TraceEntry(
                layer="L4_tool_firewall",
                latency_ms=fw_verdict.latency_ms,
                verdict="ALLOW" if fw_verdict.allowed else "DENY",
                details={
                    "reasons": fw_verdict.reasons,
                    "canary_leaked": fw_verdict.canary_leaked,
                    "exfil_detected": fw_verdict.exfil_detected,
                    "require_approval": fw_verdict.require_approval,
                },
            ))

            if not fw_verdict.allowed:
                risk_score = max(risk_score, 0.9)
                all_labels.append("TOOL_FIREWALL_DENY")
            if fw_verdict.canary_leaked:
                all_labels.append("CANARY_LEAKED")
            if fw_verdict.exfil_detected:
                all_labels.append("EXFILTRATION")

            # L5: Alignment Gate
            align_ctx = AlignmentContext(
                user_intent=request.user_intent,
                proposed_tool=request.draft_tool_call.name,
                proposed_action_summary=str(request.draft_tool_call.arguments),
                risk_score=risk_score,
                trust_zone=trust_zone.value,
                labels=all_labels,
            )
            align_verdict = self.alignment_gate.check(align_ctx)
            trace.append(TraceEntry(
                layer="L5_alignment_gate",
                latency_ms=align_verdict.latency_ms,
                score=align_verdict.confidence,
                verdict=align_verdict.action.value,
                details={
                    "aligned": align_verdict.aligned,
                    "replan_hint": align_verdict.replan_hint,
                    "approval_reason": align_verdict.approval_reason,
                },
            ))

            if not align_verdict.aligned:
                risk_score = max(risk_score, 0.8)
                all_labels.append("ALIGNMENT_MISMATCH")
        else:
            trace.append(TraceEntry(layer="L4_tool_firewall", skipped=True,
                                    details={"reason": "no tool call"}))
            trace.append(TraceEntry(layer="L5_alignment_gate", skipped=True,
                                    details={"reason": "no tool call"}))

        # --- Decision ---
        unique_labels = sorted(set(all_labels))
        if risk_score >= self.block_threshold:
            decision = Decision.BLOCK
        elif risk_score >= self.warn_threshold:
            decision = Decision.WARN
        else:
            decision = Decision.ALLOW

        total_ms = (time.perf_counter() - start) * 1000

        return ScanResponse(
            request_id=request_id,
            risk_score=round(risk_score, 4),
            labels=unique_labels,
            decision=decision,
            sanitized_context=request.retrieved_context,
            trace=trace,
        )
