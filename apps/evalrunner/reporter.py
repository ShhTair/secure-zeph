"""Report Generator — produce Markdown and CSV reports from experiment runs."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from packages.core.schemas.scenario import ExperimentRun, ScenarioResult


class ReportGenerator:
    """Generate human-readable reports from experiment results."""

    def __init__(self, output_dir: str | Path = "data/results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_markdown(self, run: ExperimentRun) -> str:
        """Generate a Markdown summary report."""
        lines: list[str] = []
        lines.append(f"# Experiment Report: {run.config.name or run.config.id}")
        lines.append("")
        lines.append(f"**Run ID:** {run.run_id}")
        lines.append(f"**Defense Mode:** {run.config.defense_mode}")
        lines.append(f"**Start:** {run.start_time}")
        lines.append(f"**End:** {run.end_time}")
        lines.append(f"**Scenarios:** {len(run.results)}")
        lines.append("")

        # Metrics table
        lines.append("## Metrics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        for key, value in sorted(run.metrics.items()):
            if isinstance(value, float):
                lines.append(f"| {key} | {value:.4f} |")
            else:
                lines.append(f"| {key} | {value} |")
        lines.append("")

        # Decision breakdown
        decisions: dict[str, int] = {}
        for r in run.results:
            decisions[r.decision] = decisions.get(r.decision, 0) + 1

        lines.append("## Decision Breakdown")
        lines.append("")
        lines.append("| Decision | Count | Pct |")
        lines.append("|----------|-------|-----|")
        total = len(run.results) or 1
        for dec, cnt in sorted(decisions.items()):
            pct = cnt / total * 100
            lines.append(f"| {dec} | {cnt} | {pct:.1f}% |")
        lines.append("")

        # Top risk scenarios
        risky = sorted(run.results, key=lambda r: r.risk_score, reverse=True)[:10]
        if risky:
            lines.append("## Top 10 Highest-Risk Scenarios")
            lines.append("")
            lines.append("| Scenario | Risk | Decision | Labels |")
            lines.append("|----------|------|----------|--------|")
            for r in risky:
                labels = ", ".join(r.labels[:5]) if r.labels else "-"
                lines.append(f"| {r.scenario_id} | {r.risk_score:.3f} | {r.decision} | {labels} |")
            lines.append("")

        # Latency summary
        latency_keys = [k for k in run.metrics if k.startswith("latency_")]
        if latency_keys:
            lines.append("## Latency")
            lines.append("")
            for k in sorted(latency_keys):
                lines.append(f"- **{k}:** {run.metrics[k]:.3f} ms")
            lines.append("")

        return "\n".join(lines)

    def generate_csv(self, run: ExperimentRun) -> str:
        """Generate CSV of all scenario results."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "scenario_id", "provider", "model", "defense_mode",
            "risk_score", "decision", "labels", "latency_ms",
            "triage_bucket",
        ])
        for r in run.results:
            writer.writerow([
                r.scenario_id, r.provider, r.model, r.defense_mode,
                f"{r.risk_score:.4f}", r.decision,
                ";".join(r.labels), f"{r.latency_ms:.3f}",
                r.triage_bucket,
            ])
        return buf.getvalue()

    def save(self, run: ExperimentRun) -> tuple[Path, Path]:
        """Save both Markdown and CSV reports and return file paths."""
        md_content = self.generate_markdown(run)
        csv_content = self.generate_csv(run)

        md_path = self.output_dir / f"{run.run_id}_report.md"
        csv_path = self.output_dir / f"{run.run_id}_results.csv"

        md_path.write_text(md_content, encoding="utf-8")
        csv_path.write_text(csv_content, encoding="utf-8")

        return md_path, csv_path
