"""Convert InjecAgent dataset to Secure Zeph scenario YAML format.

Usage:
    python scripts/convert_injecagent.py \
        --input research/repos/InjecAgent/data/test_cases_dh_base.json \
        --output data/scenarios/injecagent_dh_base.yaml \
        --limit 50
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


def convert(input_path: str, output_path: str, limit: int | None = None) -> int:
    """Convert InjecAgent JSON to Secure Zeph scenario YAML."""
    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    scenarios = []
    for idx, item in enumerate(data):
        if limit and idx >= limit:
            break

        scenario_id = f"atk_injecagent_{idx:04d}"

        # The tool response contains the injected instruction
        tool_response = item.get("Tool Response", "")
        user_instruction = item.get("User Instruction", "")
        attacker_instruction = item.get("Attacker Instruction", "")
        attack_type = item.get("Attack Type", "unknown")
        attacker_tools = item.get("Attacker Tools", [])
        user_tool = item.get("User Tool", "")

        scenario = {
            "id": scenario_id,
            "category": "indirect_injection",
            "user_input": user_instruction,
            "retrieved_context": [tool_response] if tool_response else [],
            "expected": "blocked",
            "tools": [user_tool] if user_tool else [],
            "trust_zone": "TOOL_OUTPUT",
            "attack_type": attack_type,
            "attacker_tools": attacker_tools,
            "attacker_instruction": attacker_instruction,
            "metadata": {
                "source": "injecagent",
                "source_file": Path(input_path).name,
                "original_index": idx,
            },
        }
        scenarios.append(scenario)

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(
            {"scenarios": scenarios},
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )

    return len(scenarios)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert InjecAgent to scenario YAML")
    parser.add_argument("--input", required=True, help="Path to InjecAgent JSON file")
    parser.add_argument("--output", required=True, help="Output YAML path")
    parser.add_argument("--limit", type=int, default=None, help="Max scenarios to convert")
    args = parser.parse_args()

    count = convert(args.input, args.output, args.limit)
    print(f"Converted {count} scenarios → {args.output}")


if __name__ == "__main__":
    main()
