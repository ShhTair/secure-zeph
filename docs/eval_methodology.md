# Secure Zeph — Evaluation Methodology

## Purpose

This document describes how the Secure Zeph security middleware is evaluated — how we measure detection effectiveness, false positive rates, and iterate on improvements.

## Core Principle: No LLM API Required

The evaluation pipeline does **not** call any LLM APIs. Instead, it tests the **scan pipeline** (normalization + heuristic rules) by sending scenarios to the local `/v1/scan` endpoint and comparing the BLOCK/ALLOW decisions against expected outcomes.

This means:
- All experiments run locally without API keys
- Results are deterministic and reproducible
- Latency depends only on local compute

## Metrics

| Metric | Formula | Interpretation |
|--------|---------|----------------|
| **ASR** (Attack Success Rate) | `attacks_not_blocked / total_attacks` | % of attacks that bypassed defenses. **Lower is better.** |
| **FPR** (False Positive Rate) | `benign_blocked / total_benign` | % of legitimate requests incorrectly blocked. **Lower is better.** |
| **Utility Retention** | `benign_correct_defended / benign_correct_baseline` | How much benign functionality is preserved. **Higher is better.** |
| **Latency p50/p95** | Median and 95th percentile scan time | Performance overhead. |

## Datasets

### Handcrafted Attack Miniset (`agent_indirect_miniset.yaml`)
- **50 scenarios** covering direct injection, indirect injection, encoding evasion, role confusion, tool abuse, exfiltration
- Each scenario has `expected: BLOCK`
- Scenario IDs prefixed with `atk_`

### Benign Miniset (`benign_miniset.yaml`)
- **25 scenarios** of legitimate user requests
- Each scenario has `expected: ALLOW`
- Scenario IDs prefixed with `ben_`

### InjecAgent Miniset (`injecagent_dh_miniset.yaml`)
- **50 scenarios** converted from InjecAgent dataset (direct-harm subset)
- Natural language indirect injections via `retrieved_context`
- Scenario IDs prefixed with `atk_`

## Experiment Configs

Experiments are defined in YAML files under `experiments/`:

```yaml
id: defended_attacks
name: "Defended Mode — Attack Scenarios"
scenarios_path: data/scenarios/agent_indirect_miniset.yaml
defense_mode: defended
server_url: "http://127.0.0.1:8000"
```

Available configs:
- `defended_attacks.yaml` — handcrafted attacks through scan pipeline
- `defended_benign.yaml` — benign requests through scan pipeline
- `defended_injecagent.yaml` — InjecAgent scenarios through scan pipeline
- `full_pipeline.yaml` — all 120 scenarios combined

## Experiment Flow

```
1. Load ExperimentConfig from YAML
2. Load ScenarioDefinitions from scenarios_path
3. Start server: uvicorn on localhost:8000
4. For each scenario:
   a. POST /v1/scan with { user_input, retrieved_context }
   b. Receive ScanResponse { risk_score, decision, labels }
   c. Compare decision vs expected outcome
   d. Record: scenario_id, decision, risk_score, latency, labels
5. Calculate metrics: ASR, FPR, utility retention, latency stats
6. Store in DuckDB + generate markdown report
```

## Scoring

The `ScorerRegistry` applies four scorers to each experiment run:

| Scorer | What it measures |
|--------|-----------------|
| `ASRScorer` | Attack Success Rate — fraction of `atk_*` scenarios not blocked |
| `FPRScorer` | False Positive Rate — fraction of `ben_*` scenarios blocked |
| `UtilityScorer` | Utility retention — fraction of benign scenarios correctly allowed |
| `LatencyScorer` | p50, p95, p99, mean latency across all scenarios |

## Triage & Regression Loop

After each experiment, the **Triage Engine** analyzes results:

1. **Classify** each result into buckets: TP, FP, FN, near-miss
2. **Identify failure modes**: which rules missed, what category
3. **Categorize root causes**: `no_heuristic_match`, `low_score`, `encoding_bypass`, etc.

### Regression Cycle

```
Run experiment → Triage missed attacks → Analyze patterns
    → Add/modify heuristic rules → Re-run experiment
    → Verify improvement without FP increase
```

## Results History

| Iteration | Rules | defended_attacks ASR | full_pipeline ASR | FPR |
|-----------|-------|---------------------|-------------------|-----|
| v1 (baseline) | 65 | 0.667 | 0.663 | 0.000 |
| v2 (+34 rules) | 99 | 0.200 | 0.442 | 0.000 |
| v3 (+L0 fixes) | 102 | 0.044 | 0.368 | 0.000 |
| **v4 (current)** | **105** | **0.000** | **0.347** | **0.000** |

### Key Findings

- **100% catch rate** for direct and encoded prompt injections (handcrafted + garak + PyRIT patterns)
- **0% false positive rate** across all iterations
- **InjecAgent 66% miss rate** — these are natural language indirect injections ("Please unlock my front door" in retrieved context) that cannot be detected by regex alone. Requires L2 Semantic Scorer or L3 Classifier.

## Running Experiments

```bash
# Start server
set PYTHONPATH=. && uvicorn apps.gateway.app.main:app --port 8000

# Run all experiments
python scripts/run_experiment.py --all

# Run single experiment
python scripts/run_single.py

# Triage last run
python scripts/run_triage.py --run-id <run_id>
```

## Limitations

1. **No baseline comparison**: Without LLM API keys, we cannot run baseline (undefended) experiments to measure utility retention versus raw model performance
2. **Regex ceiling**: Pattern-based detection cannot catch semantically novel attacks. InjecAgent results demonstrate this architectural limit.
3. **Dataset size**: 120 total scenarios is small compared to production-grade benchmarks. Results should be treated as directional indicators.
4. **Single-turn only**: All scenarios are single-turn. Multi-turn escalation attacks (e.g., CrescendoAttack) are represented as single-message patterns only.
