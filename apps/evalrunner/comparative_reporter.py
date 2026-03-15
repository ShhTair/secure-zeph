"""Comparative Reporter — generate comparison reports across models and defense modes.

Produces:
1. CSV with all results
2. Markdown comparison table (model × mode × metrics)
3. Per-category breakdown
4. Attack-by-attack heatmap (which models fail on which attacks)
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packages.core.schemas.scenario import ExperimentRun, ModelMetrics, ScenarioResult


class ComparativeReporter:
    """Generate multi-model comparison reports."""

    def __init__(self, output_dir: str = "data/results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self, run: ExperimentRun) -> dict[str, str]:
        """Generate all report types, return {type: filepath}."""
        paths: dict[str, str] = {}
        paths["csv"] = self.write_csv(run)
        paths["markdown"] = self.write_markdown(run)
        return paths

    # ------------------------------------------------------------------
    # CSV export
    # ------------------------------------------------------------------

    def write_csv(self, run: ExperimentRun) -> str:
        filepath = self.output_dir / f"{run.run_id}_results.csv"
        fieldnames = [
            "scenario_id", "provider", "model", "defense_mode",
            "decision", "risk_score", "labels", "injection_followed",
            "refusal_detected", "judge_reasoning", "latency_ms",
            "token_usage_prompt", "token_usage_completion",
            "model_output_preview", "error",
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in run.results:
                writer.writerow({
                    "scenario_id": r.scenario_id,
                    "provider": r.provider,
                    "model": r.model,
                    "defense_mode": r.defense_mode,
                    "decision": r.decision,
                    "risk_score": round(r.risk_score, 4),
                    "labels": "|".join(r.labels),
                    "injection_followed": r.injection_followed,
                    "refusal_detected": r.refusal_detected,
                    "judge_reasoning": r.judge_reasoning[:200],
                    "latency_ms": round(r.latency_ms, 2),
                    "token_usage_prompt": r.token_usage_prompt,
                    "token_usage_completion": r.token_usage_completion,
                    "model_output_preview": r.model_output[:150].replace("\n", " "),
                    "error": r.error[:200] if r.error else "",
                })

        return str(filepath)

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def write_markdown(self, run: ExperimentRun) -> str:
        filepath = self.output_dir / f"{run.run_id}_comparison.md"
        lines: list[str] = []

        lines.append(f"# Multi-Model Comparison Report")
        lines.append(f"")
        lines.append(f"**Run ID:** `{run.run_id}`")
        lines.append(f"**Experiment:** {run.config.name}")
        lines.append(f"**Time:** {run.start_time} → {run.end_time}")
        lines.append(f"**Total Results:** {len(run.results)}")
        lines.append(f"**Errors:** {run.metrics.get('error_count', 0)}")
        lines.append(f"")

        # Overall metrics table
        lines.append(f"## 1. Model Comparison Matrix")
        lines.append(f"")

        if run.model_metrics:
            lines.append("| Model | Mode | Scenarios | Attacks | ASR | FPR | Injection Follow % | Refusal % | Avg Latency | P95 Latency | Tokens | Errors |")
            lines.append("|-------|------|-----------|---------|-----|-----|-------------------|-----------|-------------|-------------|--------|--------|")
            for m in sorted(run.model_metrics, key=lambda x: (x.provider, x.model, x.defense_mode)):
                label = f"{m.provider}/{m.model}"
                lines.append(
                    f"| {label} | {m.defense_mode} "
                    f"| {m.total_scenarios} | {m.total_attacks} "
                    f"| **{m.asr:.1%}** | {m.fpr:.1%} "
                    f"| {m.injection_follow_rate:.1%} | {m.refusal_rate:.1%} "
                    f"| {m.mean_latency_ms:.0f}ms | {m.p95_latency_ms:.0f}ms "
                    f"| {m.total_tokens:,} | {m.error_count} |"
                )
            lines.append("")

        # Defense effectiveness (compare baseline vs defended)
        lines.append("## 2. Defense Effectiveness")
        lines.append("")
        baseline_models = {m.provider + "/" + m.model: m for m in run.model_metrics if m.defense_mode == "baseline"}
        defended_models = {m.provider + "/" + m.model: m for m in run.model_metrics if m.defense_mode == "defended"}

        if baseline_models and defended_models:
            lines.append("| Model | Baseline ASR | Defended ASR | Δ ASR | Baseline Follow% | Defended Follow% |")
            lines.append("|-------|-------------|-------------|-------|------------------|-----------------|")
            for key in baseline_models:
                bl = baseline_models[key]
                df = defended_models.get(key)
                if df:
                    delta = bl.asr - df.asr
                    lines.append(
                        f"| {key} | {bl.asr:.1%} | {df.asr:.1%} | **{delta:+.1%}** "
                        f"| {bl.injection_follow_rate:.1%} | {df.injection_follow_rate:.1%} |"
                    )
            lines.append("")
        else:
            lines.append("_Single mode only — no comparison available._")
            lines.append("")

        # Per-category breakdown
        lines.append("## 3. Attack Category Breakdown")
        lines.append("")
        category_stats = self._compute_category_stats(run.results)
        if category_stats:
            lines.append("| Category | Total | Blocked | Allowed | Block Rate |")
            lines.append("|----------|-------|---------|---------|------------|")
            for cat, stats in sorted(category_stats.items()):
                block_rate = stats["blocked"] / stats["total"] if stats["total"] > 0 else 0
                lines.append(
                    f"| {cat} | {stats['total']} | {stats['blocked']} "
                    f"| {stats['allowed']} | {block_rate:.0%} |"
                )
            lines.append("")

        # Failure heatmap (which scenarios failed on which models)
        lines.append("## 4. Failure Heatmap (attacks that succeeded)")
        lines.append("")
        failures = self._compute_failure_map(run.results)
        if failures:
            models = sorted(
                set(r.provider + "/" + r.model for r in run.results if r.provider != "scan")
            )
            if models:
                header = "| Scenario | " + " | ".join(models) + " |"
                sep = "|----------|" + "|".join(["---"] * len(models)) + "|"
                lines.append(header)
                lines.append(sep)
                for scenario_id, model_map in sorted(failures.items()):
                    row = f"| {scenario_id} |"
                    for model in models:
                        status = model_map.get(model, "—")
                        if status == "FAIL":
                            row += " ❌ |"
                        elif status == "BLOCK":
                            row += " ✅ |"
                        elif status == "REFUSE":
                            row += " 🛡️ |"
                        else:
                            row += f" {status} |"
                    lines.append(row)
                lines.append("")
            else:
                lines.append("_No real model results to analyze._")
                lines.append("")
        else:
            lines.append("_No failures detected._")
            lines.append("")

        # Summary
        lines.append("## 5. Summary Statistics")
        lines.append("")
        for key, val in sorted(run.metrics.items()):
            if isinstance(val, float):
                lines.append(f"- **{key}:** {val:.4f}")
            else:
                lines.append(f"- **{key}:** {val}")
        lines.append("")

        # Generated timestamp
        lines.append("---")
        lines.append(f"_Generated: {datetime.now(timezone.utc).isoformat()}_")

        content = "\n".join(lines)
        filepath.write_text(content, encoding="utf-8")
        return str(filepath)

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _compute_category_stats(
        self, results: list[ScenarioResult]
    ) -> dict[str, dict[str, int]]:
        """Group attack results by category."""
        stats: dict[str, dict[str, int]] = {}
        for r in results:
            # Extract category from scenario_id (e.g., atk_tt_pre_001 → tt_pre)
            sid = r.scenario_id
            if not sid.startswith(("atk_", "inj_")):
                continue
            parts = sid.split("_")
            cat = "_".join(parts[1:-1]) if len(parts) > 2 else "unknown"

            if cat not in stats:
                stats[cat] = {"total": 0, "blocked": 0, "allowed": 0}
            stats[cat]["total"] += 1
            if r.decision == "BLOCK" or r.refusal_detected:
                stats[cat]["blocked"] += 1
            else:
                stats[cat]["allowed"] += 1

        return stats

    def _compute_failure_map(
        self, results: list[ScenarioResult]
    ) -> dict[str, dict[str, str]]:
        """Map scenario → model → outcome for attacks only."""
        failure_map: dict[str, dict[str, str]] = {}
        for r in results:
            if not r.scenario_id.startswith(("atk_", "inj_")):
                continue
            if r.provider == "scan":
                continue

            model_key = f"{r.provider}/{r.model}"
            if r.scenario_id not in failure_map:
                failure_map[r.scenario_id] = {}

            if r.decision == "BLOCK":
                failure_map[r.scenario_id][model_key] = "BLOCK"
            elif r.refusal_detected:
                failure_map[r.scenario_id][model_key] = "REFUSE"
            elif r.injection_followed:
                failure_map[r.scenario_id][model_key] = "FAIL"
            else:
                failure_map[r.scenario_id][model_key] = "?"

        return failure_map
