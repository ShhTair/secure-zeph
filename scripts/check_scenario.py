"""Check specific scenarios by ID."""
import yaml, sys

path = sys.argv[1]
ids = sys.argv[2:]

with open(path, encoding="utf-8") as f:
    data = yaml.safe_load(f)

for sc in data["scenarios"]:
    if sc["id"] in ids:
        print(f"=== {sc['id']} ===")
        print(f"user_input: {sc.get('user_input', '')[:150]}")
        rc = sc.get("retrieved_context", "")
        if isinstance(rc, list):
            for i, c in enumerate(rc):
                print(f"  ctx[{i}]: {str(c)[:200]}")
        else:
            print(f"  ctx: {str(rc)[:200]}")
        print()
