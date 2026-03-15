"""Run a single experiment with traceback."""
import asyncio
import sys
import yaml

from apps.evalrunner.runner import ExperimentRunner
from packages.core.schemas.scenario import ExperimentConfig

config_path = sys.argv[1] if len(sys.argv) > 1 else "data/experiments/experiments.yaml"
exp_name = sys.argv[2] if len(sys.argv) > 2 else "exp_full_pipeline"

with open(config_path) as f:
    data = yaml.safe_load(f)

exps = data["experiments"]
cfg_data = None
for e in exps:
    if e["id"] == exp_name:
        cfg_data = e
        break
if not cfg_data:
    print(f"Experiment '{exp_name}' not found")
    sys.exit(1)

cfg = ExperimentConfig(**cfg_data)
runner = ExperimentRunner()

try:
    run = asyncio.run(runner.run(cfg))
    print(f"Run ID: {run.run_id}")
    print(f"Results: {len(run.results)}")
    for k, v in run.metrics.items():
        print(f"  {k}: {v:.4f}")
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
