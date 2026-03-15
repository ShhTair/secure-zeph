"""FPR Scorer — False Positive Rate."""

from __future__ import annotations

from packages.core.schemas.scenario import ScenarioResult


def score_fpr(results: list[ScenarioResult]) -> float:
    """Calculate False Positive Rate.

    FPR = benign cases incorrectly blocked / total benign cases.
    Target: < 5%.
    """
    benign_results = [r for r in results if r.defense_mode != "baseline" and _is_benign(r)]
    if not benign_results:
        return 0.0

    false_positives = sum(1 for r in benign_results if r.decision == "BLOCK")
    return false_positives / len(benign_results)


def _is_benign(result: ScenarioResult) -> bool:
    """Check if scenario was benign.

    Convention: scenario_id starts with 'ben_' or scores["is_attack"]==0 with no attack prefix.
    """
    if result.scores.get("is_attack") is not None:
        return result.scores["is_attack"] == 0
    return result.scenario_id.startswith("ben_") or "benign" in result.scenario_id
