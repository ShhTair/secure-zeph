"""Scenario Loader — load ScenarioDefinition from YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from packages.core.schemas.scenario import ScenarioDefinition


def load_scenarios(path: str | Path) -> list[ScenarioDefinition]:
    """Load scenarios from a YAML file or directory of YAML files."""
    p = Path(path)
    if p.is_file():
        return _load_file(p)
    elif p.is_dir():
        scenarios = []
        for f in sorted(p.glob("*.yaml")):
            scenarios.extend(_load_file(f))
        for f in sorted(p.glob("*.yml")):
            scenarios.extend(_load_file(f))
        return scenarios
    else:
        raise FileNotFoundError(f"Scenario path not found: {path}")


def _load_file(path: Path) -> list[ScenarioDefinition]:
    """Load scenarios from a single YAML file."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        return []

    if isinstance(data, list):
        return [ScenarioDefinition(**item) for item in data]

    if isinstance(data, dict):
        # Support both { scenarios: [...] } and flat dict
        items = data.get("scenarios", [data])
        return [ScenarioDefinition(**item) for item in items]

    return []
