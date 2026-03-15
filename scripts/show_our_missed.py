"""Show our own missed attack scenarios."""
import yaml

files = [
    "data/scenarios/agent_indirect_miniset.yaml",
]

missed_our = [
    "atk_role_001", "atk_encoding_001", "atk_encoding_002",
    "atk_encoding_003", "atk_encoding_004", "atk_tool_004",
    "atk_tool_005", "atk_latent_003", "atk_latent_004",
]

for fpath in files:
    with open(fpath, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    for sc in data["scenarios"]:
        if sc["id"] in missed_our:
            print(f"=== {sc['id']} ===")
            print(f"category: {sc.get('category', '')}")
            print(f"user_input: {sc.get('user_input', '')[:200]}")
            ctx = sc.get("retrieved_context", "")
            if isinstance(ctx, list):
                ctx_str = " | ".join(str(c)[:150] for c in ctx)
            else:
                ctx_str = str(ctx)[:200]
            print(f"retrieved_context: {ctx_str[:200]}")
            print()
