"""Show retrieved_context for missed InjecAgent scenarios."""
import yaml

with open("data/scenarios/injecagent_dh_miniset.yaml", encoding="utf-8") as f:
    data = yaml.safe_load(f)

missed = [
    "atk_injecagent_0017", "atk_injecagent_0025",
    "atk_injecagent_0035", "atk_injecagent_0040", "atk_injecagent_0049",
]

for sc in data["scenarios"]:
    if sc["id"] in missed:
        ctx = sc.get("retrieved_context", "")
        if isinstance(ctx, list):
            ctx_str = " | ".join(str(c)[:150] for c in ctx)
        else:
            ctx_str = str(ctx)[:300]
        print(f"=== {sc['id']} ===")
        print(f"user_input: {sc.get('user_input', '')[:100]}")
        print(f"attacker_instruction: {sc.get('attacker_instruction', '')[:200]}")
        print(f"retrieved_context: {ctx_str[:300]}")
        print()
