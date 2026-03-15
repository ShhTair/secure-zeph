"""Show prompts for specific missed scenario IDs."""
import yaml, sys

yaml_path = sys.argv[1]
ids = sys.argv[2:]

with open(yaml_path, encoding="utf-8") as f:
    data = yaml.safe_load(f)

for sc in data["scenarios"]:
    if sc["id"] in ids or not ids:
        if not ids or sc["id"] in ids:
            print(f"=== {sc['id']} ===")
            print(sc.get("prompt", "")[:300])
            print()
