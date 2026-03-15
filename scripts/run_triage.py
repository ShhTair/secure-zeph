"""Run triage analysis on stored experiment results.

Usage:
    python scripts/run_triage.py --run-id run_5273bff9ba8b
    python scripts/run_triage.py --latest
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from apps.evalrunner.triage import TriageEngine, TriageReport
from packages.core.schemas.scenario import ScenarioResult
from packages.core.storage.duckdb_store import DuckDBStore


def _rows_to_results(rows: list[dict]) -> list[ScenarioResult]:
    """Convert DuckDB rows back to ScenarioResult objects."""
    results = []
    for row in rows:
        results.append(ScenarioResult(
            scenario_id=row["scenario_id"],
            provider=row["provider"],
            model=row.get("model", ""),
            defense_mode=row.get("defense_mode", "defended"),
            model_output=row.get("model_output", ""),
            risk_score=row.get("risk_score", 0.0),
            decision=row.get("decision", "ALLOW"),
            labels=json.loads(row.get("labels_json", "[]")),
            scan_trace=json.loads(row.get("trace_json", "[]")),
            scores=json.loads(row.get("scores_json", "{}")),
            latency_ms=row.get("latency_ms", 0.0),
            triage_bucket=row.get("triage_bucket", ""),
        ))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage missed attacks")
    parser.add_argument("--run-id", help="Specific run ID to triage")
    parser.add_argument("--latest", action="store_true", help="Triage latest run")
    parser.add_argument("--output", help="Output path for triage report (optional)")
    args = parser.parse_args()

    store = DuckDBStore()

    if args.latest:
        runs = store.list_runs()
        if not runs:
            print("No runs found.")
            return
        run_id = runs[0]["run_id"]
        print(f"Using latest run: {run_id}")
    elif args.run_id:
        run_id = args.run_id
    else:
        print("Specify --run-id or --latest")
        return

    rows = store.query_results(run_id=run_id)
    if not rows:
        print(f"No results found for run {run_id}")
        return

    results = _rows_to_results(rows)

    engine = TriageEngine()
    report = engine.analyze(results)
    md = engine.generate_report(report)

    print(md)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"\nSaved to: {out}")
    else:
        # Save next to results
        out = Path(f"data/results/{run_id}_triage.md")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"\nSaved to: {out}")

    store.close()


if __name__ == "__main__":
    main()
