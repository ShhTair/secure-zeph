"""Run experiments from config YAML.

Usage:
    python scripts/run_experiment.py --config data/experiments/experiments.yaml --experiment exp_defended_attacks
    python scripts/run_experiment.py --config data/experiments/experiments.yaml --all
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import yaml

from apps.evalrunner.reporter import ReportGenerator
from apps.evalrunner.runner import ExperimentRunner
from packages.core.schemas.scenario import ExperimentConfig
from packages.core.storage.duckdb_store import DuckDBStore


def load_experiment_configs(path: str) -> list[ExperimentConfig]:
    """Load experiment configs from YAML."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return [ExperimentConfig(**item) for item in data.get("experiments", [])]


async def run_single(config: ExperimentConfig, store: DuckDBStore, reporter: ReportGenerator) -> None:
    """Run a single experiment."""
    print(f"\n{'='*60}")
    print(f"  Experiment: {config.name or config.id}")
    print(f"  Mode: {config.defense_mode}")
    print(f"  Scenarios: {config.scenarios_path}")
    print(f"{'='*60}")

    runner = ExperimentRunner()
    run = await runner.run(config)

    # Save to DuckDB
    store.save_run(run)

    # Generate reports
    md_path, csv_path = reporter.save(run)

    print(f"\n  Run ID: {run.run_id}")
    print(f"  Scenarios: {len(run.results)}")
    print(f"  Metrics:")
    for k, v in sorted(run.metrics.items()):
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")
    print(f"  Report: {md_path}")
    print(f"  CSV:    {csv_path}")


async def main_async(args: argparse.Namespace) -> None:
    configs = load_experiment_configs(args.config)
    store = DuckDBStore()
    reporter = ReportGenerator()

    if args.all:
        for config in configs:
            await run_single(config, store, reporter)
    elif args.experiment:
        matching = [c for c in configs if c.id == args.experiment]
        if not matching:
            print(f"Experiment '{args.experiment}' not found. Available:")
            for c in configs:
                print(f"  - {c.id}: {c.name}")
            sys.exit(1)
        for config in matching:
            await run_single(config, store, reporter)
    else:
        print("Specify --experiment <id> or --all")
        sys.exit(1)

    store.close()
    print("\nDone.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run evaluation experiments")
    parser.add_argument("--config", required=True, help="Path to experiments YAML")
    parser.add_argument("--experiment", help="Experiment ID to run")
    parser.add_argument("--all", action="store_true", help="Run all experiments")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
