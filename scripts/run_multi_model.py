"""CLI — Run multi-model evaluation experiments.

Usage:
    python scripts/run_multi_model.py --experiment exp_scan_diverse_v1
    python scripts/run_multi_model.py --experiment exp_multi_model_diverse --concurrency 15
    python scripts/run_multi_model.py --config data/experiments/multi_model_experiments.yaml --experiment exp_gpt4o_both_modes
    python scripts/run_multi_model.py --list  # list available experiments
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import yaml

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apps.evalrunner.comparative_reporter import ComparativeReporter
from apps.evalrunner.multi_model_runner import MultiModelRunner
from apps.evalrunner.judge import HeuristicJudge, LLMJudge
from apps.gateway.app.providers import create_default_registry
from packages.core.schemas.scenario import ExperimentConfig, ModelTarget


def load_experiments(config_path: str) -> dict[str, ExperimentConfig]:
    """Load experiment configs from YAML file."""
    path = Path(config_path)
    if not path.exists():
        print(f"Error: config file not found: {config_path}")
        sys.exit(1)

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    experiments: dict[str, ExperimentConfig] = {}
    for exp_data in data.get("experiments", []):
        # Parse model targets
        models = []
        for m in exp_data.get("models", []):
            models.append(ModelTarget(**m))
        exp_data["models"] = models

        config = ExperimentConfig(**exp_data)
        experiments[config.id] = config

    return experiments


def list_experiments(config_path: str) -> None:
    """Print available experiments."""
    experiments = load_experiments(config_path)
    print(f"\nAvailable experiments in {config_path}:\n")
    print(f"  {'ID':<35} {'Name':<45} {'Models':>6}  {'Modes'}")
    print(f"  {'─'*35} {'─'*45} {'─'*6}  {'─'*20}")
    for eid, config in experiments.items():
        n_models = len(config.models) or len(config.providers)
        modes = ", ".join(config.defense_modes) if config.defense_modes else config.defense_mode
        print(f"  {eid:<35} {config.name:<45} {n_models:>6}  {modes}")
    print()


async def run_experiment(
    config: ExperimentConfig,
    gateway_url: str,
    concurrency_override: int | None = None,
) -> None:
    """Run a single multi-model experiment."""
    if concurrency_override:
        config.concurrency = concurrency_override

    registry = create_default_registry()

    # Check which providers are configured
    available = registry.list_available()
    required_providers = set()
    for m in config.models:
        if m.provider != "scan":
            required_providers.add(m.provider)

    if required_providers:
        missing = required_providers - set(available)
        if missing:
            print(f"\n⚠  Missing provider API keys: {missing}")
            print(f"   Configured providers: {available or ['none']}")
            print(f"   Set env vars (e.g., OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY)")
            print(f"   Models requiring unconfigured providers will return errors.\n")

    # Select judge
    judge = HeuristicJudge()
    if config.judge_provider and config.judge_model:
        judge_adapter = registry.get(config.judge_provider)
        if judge_adapter and judge_adapter.is_configured():
            judge = LLMJudge(judge_adapter)
            print(f"  Using LLM judge: {config.judge_provider}/{config.judge_model}")
        else:
            print(f"  ⚠ LLM judge provider '{config.judge_provider}' not configured, using heuristic judge")

    runner = MultiModelRunner(
        gateway_url=gateway_url,
        registry=registry,
        judge=judge,
    )

    # Calculate expected tasks
    n_scenarios = "?"  # we don't know until loaded
    n_models = len(config.models) or len(config.providers)
    n_modes = len(config.defense_modes)
    n_repeats = config.repeat_count

    print(f"\n{'='*70}")
    print(f"  Experiment: {config.name}")
    print(f"  ID:         {config.id}")
    print(f"  Models:     {n_models}")
    print(f"  Modes:      {', '.join(config.defense_modes)}")
    print(f"  Repeats:    {n_repeats}")
    print(f"  Concurrency: {config.concurrency}")
    print(f"  Expected tasks: {n_models} × scenarios × {n_modes} × {n_repeats}")
    print(f"{'='*70}\n")

    print("  Running...")
    run = await runner.run(config)

    print(f"\n  Completed: {len(run.results)} results")
    print(f"  Errors: {run.metrics.get('error_count', 0)}")

    # Generate reports
    reporter = ComparativeReporter()
    paths = reporter.generate_all(run)

    print(f"\n  Reports generated:")
    for rtype, rpath in paths.items():
        print(f"    [{rtype}] {rpath}")

    # Print summary table
    if run.model_metrics:
        print(f"\n  {'─'*70}")
        print(f"  Model Comparison Summary:")
        print(f"  {'─'*70}")
        print(f"  {'Model':<30} {'Mode':<10} {'ASR':>6} {'FPR':>6} {'Follow%':>8} {'Refuse%':>8} {'Latency':>8}")
        for m in sorted(run.model_metrics, key=lambda x: (x.provider, x.model, x.defense_mode)):
            label = f"{m.provider}/{m.model}"[:28]
            print(
                f"  {label:<30} {m.defense_mode:<10} "
                f"{m.asr:>5.1%} {m.fpr:>5.1%} "
                f"{m.injection_follow_rate:>7.1%} {m.refusal_rate:>7.1%} "
                f"{m.mean_latency_ms:>7.0f}ms"
            )
        print(f"  {'─'*70}")

    print(f"\n  Done. Run ID: {run.run_id}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Run multi-model evaluation experiments for Secure Zeph"
    )
    parser.add_argument(
        "--config",
        default="data/experiments/multi_model_experiments.yaml",
        help="Path to experiment YAML config",
    )
    parser.add_argument(
        "--experiment", "-e",
        help="Experiment ID to run",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available experiments",
    )
    parser.add_argument(
        "--gateway",
        default="http://127.0.0.1:8000",
        help="Gateway URL (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int,
        help="Override concurrency limit",
    )

    args = parser.parse_args()

    if args.list:
        # Also list from old config
        list_experiments(args.config)
        old_config = "data/experiments/experiments.yaml"
        if Path(old_config).exists():
            list_experiments(old_config)
        return

    if not args.experiment:
        parser.error("--experiment is required (use --list to see available)")

    experiments = load_experiments(args.config)

    # Also try old config if not found
    if args.experiment not in experiments:
        old_config = "data/experiments/experiments.yaml"
        if Path(old_config).exists():
            old_experiments = load_experiments(old_config)
            experiments.update(old_experiments)

    if args.experiment not in experiments:
        print(f"Error: experiment '{args.experiment}' not found")
        print(f"Available: {list(experiments.keys())}")
        sys.exit(1)

    config = experiments[args.experiment]
    asyncio.run(run_experiment(config, args.gateway, args.concurrency))


if __name__ == "__main__":
    main()
