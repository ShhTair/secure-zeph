"""Analyze missed attacks from experiment CSV."""
import csv
import sys

csv_path = sys.argv[1] if len(sys.argv) > 1 else "data/results/run_35566140cce3_results.csv"

with open(csv_path, encoding="utf-8") as f:
    reader = csv.DictReader(f)
    rows = list(reader)

missed = [r for r in rows if r["decision"] != "BLOCK" and r["scenario_id"].startswith("atk_")]
print(f"Missed: {len(missed)}\n")

for r in missed:
    sid = r["scenario_id"]
    risk = r.get("risk_score", "?")
    labels = r.get("labels", "")
    bucket = r.get("triage_bucket", "")
    print(f"{sid}: risk={risk}, labels=[{labels}], bucket={bucket}")
    print()
