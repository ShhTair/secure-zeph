"""Policy Loader — parse YAML policy files into in-memory rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from packages.core.policy.engine import LocalPolicyEngine


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a single YAML file, returning empty dict if missing."""
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_policies(policies_dir: str | Path = "policies") -> dict[str, Any]:
    """Load all policy YAML files from the policies directory."""
    base = Path(policies_dir)
    return {
        "tools": load_yaml(base / "default_tools.yaml"),
        "trust": load_yaml(base / "trust_zones.yaml"),
        "exfil": load_yaml(base / "exfil_controls.yaml"),
        "approval": load_yaml(base / "approval_gates.yaml"),
        "canary": load_yaml(Path("data") / "canary_tokens.yaml"),
    }


def create_policy_engine(policies_dir: str | Path = "policies") -> LocalPolicyEngine:
    """Create a fully-loaded LocalPolicyEngine from YAML files."""
    policies = load_policies(policies_dir)
    return LocalPolicyEngine(policies)
