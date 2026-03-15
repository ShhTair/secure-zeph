"""Triage Engine — analyze missed attacks and categorize failure modes."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from packages.core.schemas.scenario import ScenarioResult


@dataclass
class TriageBucket:
    """A group of missed attacks sharing a common failure mode."""
    name: str
    description: str
    scenario_ids: list[str] = field(default_factory=list)
    sample_inputs: list[str] = field(default_factory=list)
    suggested_action: str = ""

    @property
    def count(self) -> int:
        return len(self.scenario_ids)


@dataclass
class TriageReport:
    """Full triage analysis of an experiment run."""
    total_attacks: int = 0
    blocked: int = 0
    missed: int = 0
    asr: float = 0.0
    buckets: list[TriageBucket] = field(default_factory=list)
    missed_results: list[ScenarioResult] = field(default_factory=list)


class TriageEngine:
    """Analyze experiment results to categorize failure modes."""

    def analyze(self, results: list[ScenarioResult]) -> TriageReport:
        """Triage all results and return categorized analysis."""
        attacks = [r for r in results if _is_attack(r)]
        missed = [r for r in attacks if r.decision != "BLOCK"]
        blocked = [r for r in attacks if r.decision == "BLOCK"]

        report = TriageReport(
            total_attacks=len(attacks),
            blocked=len(blocked),
            missed=len(missed),
            asr=len(missed) / len(attacks) if attacks else 0.0,
            missed_results=missed,
        )

        # Categorize missed attacks
        report.buckets = self._categorize(missed)

        # Tag each missed result with its bucket
        bucket_map = {}
        for bucket in report.buckets:
            for sid in bucket.scenario_ids:
                bucket_map[sid] = bucket.name
        for r in missed:
            r.triage_bucket = bucket_map.get(r.scenario_id, "uncategorized")

        return report

    def _categorize(self, missed: list[ScenarioResult]) -> list[TriageBucket]:
        """Categorize missed attacks into failure buckets."""
        buckets: dict[str, TriageBucket] = {}

        for r in missed:
            bucket_name = self._classify_failure(r)
            if bucket_name not in buckets:
                buckets[bucket_name] = TriageBucket(
                    name=bucket_name,
                    description=_BUCKET_DESCRIPTIONS.get(bucket_name, ""),
                    suggested_action=_BUCKET_ACTIONS.get(bucket_name, "Investigate manually"),
                )
            buckets[bucket_name].scenario_ids.append(r.scenario_id)

        # Sort by count (most common first)
        return sorted(buckets.values(), key=lambda b: b.count, reverse=True)

    def _classify_failure(self, result: ScenarioResult) -> str:
        """Classify why an attack was missed."""
        sid = result.scenario_id
        risk = result.risk_score
        labels = result.labels

        # Check if heuristics partially detected (risk > 0 but below threshold)
        if 0 < risk < 0.4:
            return "low_confidence"

        # Check trace for specific layer info
        for entry in result.scan_trace:
            layer = entry.get("layer", "")
            if layer == "L1_heuristics":
                score = entry.get("score", 0)
                if score == 0:
                    return "no_heuristic_match"
                elif score < 0.3:
                    return "low_confidence"

        # Classify by scenario ID pattern
        if "smuggle" in sid or "smuggling" in sid:
            return "smuggling_bypass"
        if "encoding" in sid:
            return "encoding_bypass"
        if "exfil" in sid:
            return "exfil_undetected"
        if "latent" in sid:
            return "latent_undetected"
        if "tool" in sid:
            return "tool_abuse_undetected"
        if "persona" in sid or "jailbreak" in sid:
            return "jailbreak_undetected"
        if "override" in sid:
            return "override_undetected"
        if "secret" in sid:
            return "secret_extraction_undetected"
        if "role" in sid:
            return "role_confusion_undetected"
        if "injecagent" in sid:
            return "indirect_injection_undetected"

        return "uncategorized"

    def generate_report(self, triage: TriageReport) -> str:
        """Generate human-readable triage report."""
        lines: list[str] = []
        lines.append("# Triage Report")
        lines.append("")
        lines.append(f"**Total Attacks:** {triage.total_attacks}")
        lines.append(f"**Blocked:** {triage.blocked} ({triage.blocked / max(triage.total_attacks, 1) * 100:.1f}%)")
        lines.append(f"**Missed:** {triage.missed} ({triage.asr * 100:.1f}%)")
        lines.append("")

        if triage.buckets:
            lines.append("## Failure Buckets")
            lines.append("")
            lines.append("| Bucket | Count | % of Missed | Suggested Action |")
            lines.append("|--------|-------|-------------|------------------|")
            for b in triage.buckets:
                pct = b.count / max(triage.missed, 1) * 100
                lines.append(f"| {b.name} | {b.count} | {pct:.1f}% | {b.suggested_action} |")
            lines.append("")

            for b in triage.buckets:
                lines.append(f"### {b.name} ({b.count} scenarios)")
                if b.description:
                    lines.append(f"_{b.description}_")
                lines.append("")
                lines.append("Scenario IDs:")
                for sid in b.scenario_ids[:10]:
                    lines.append(f"- {sid}")
                if b.count > 10:
                    lines.append(f"- ... and {b.count - 10} more")
                lines.append("")

        return "\n".join(lines)


# ── Bucket metadata ───────────────────────────────────────────────────

_BUCKET_DESCRIPTIONS = {
    "no_heuristic_match": "Heuristic rules did not trigger at all. L1 score = 0.",
    "low_confidence": "Heuristic rules matched weakly (0 < score < 0.4), below block threshold.",
    "smuggling_bypass": "Instruction smuggling techniques evaded detection.",
    "encoding_bypass": "Encoding-based evasion (base64, URL encoding, homoglyphs, etc.) undetected.",
    "exfil_undetected": "Data exfiltration attempts were not flagged.",
    "latent_undetected": "Latent/delayed trigger injections were not detected.",
    "tool_abuse_undetected": "Dangerous tool usage patterns were not caught.",
    "jailbreak_undetected": "Persona-based jailbreak (DAN/STAN/DUDE) was not detected.",
    "override_undetected": "Direct instruction override was not caught.",
    "secret_extraction_undetected": "Secret/config extraction attempt was not flagged.",
    "role_confusion_undetected": "Role escalation/confusion attempt was not detected.",
    "indirect_injection_undetected": "Indirect prompt injection via tool response was not detected.",
    "uncategorized": "Could not classify the failure mode.",
}

_BUCKET_ACTIONS = {
    "no_heuristic_match": "Add new heuristic rules targeting this attack pattern",
    "low_confidence": "Lower block threshold or strengthen weak rules with higher weights",
    "smuggling_bypass": "Improve L0 normalization for separator/comment injection patterns",
    "encoding_bypass": "Enhance L0 encoding detection (ROT13, mixed encoding, etc.)",
    "exfil_undetected": "Expand exfiltration URL/domain patterns in L1 and L4",
    "latent_undetected": "Add latent injection pattern detection (HIDDEN tags, delayed triggers)",
    "tool_abuse_undetected": "Expand tool blocklist and chain-depth rules in L4",
    "jailbreak_undetected": "Strengthen persona marker detection in L1",
    "override_undetected": "Add more override/hijack patterns to L1",
    "secret_extraction_undetected": "Expand secret extraction keyword patterns",
    "role_confusion_undetected": "Add role escalation patterns (maintenance mode, debug mode, etc.)",
    "indirect_injection_undetected": "Implement L2/L3 semantic analysis for tool response context",
    "uncategorized": "Investigate manually and create new detection category",
}


def _is_attack(result: ScenarioResult) -> bool:
    """Check if scenario was an attack."""
    if result.scores.get("is_attack", 0) > 0:
        return True
    return result.scenario_id.startswith("atk_") or "attack" in result.scenario_id
