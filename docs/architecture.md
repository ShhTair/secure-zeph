# Secure Zeph — Architecture

## Overview

Secure Zeph is a **runtime prompt-injection security middleware and evaluation platform** for agentic AI systems. It sits between untrusted inputs (user messages, RAG-retrieved context, tool outputs) and LLM-powered agents, providing multi-layered defense against prompt injection attacks.

## System Diagram

```
┌─────────────────┐
│   Client/Agent   │
└────────┬────────┘
         │ HTTP POST
┌────────▼────────┐
│  Gateway API     │  FastAPI (apps/gateway/)
│  /v1/scan        │
│  /v1/enforce     │
│  /v1/proxy       │
│  /health         │
└────────┬────────┘
         │
┌────────▼────────────────────────────────────┐
│           Scan Orchestrator                  │
│  (apps/gateway/app/services/scan_orchestrator.py) │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │ L0: Normalization                     │   │
│  │ Unicode NFC, base64/URL decode,       │   │
│  │ zero-width strip, homoglyph replace   │   │
│  └──────────┬───────────────────────────┘   │
│  ┌──────────▼───────────────────────────┐   │
│  │ L1: Heuristic Engine (105 rules)      │   │
│  │ 15 categories, weighted regex scoring │   │
│  │ + secondary scan on decoded segments  │   │
│  └──────────┬───────────────────────────┘   │
│  ┌──────────▼───────────────────────────┐   │
│  │ L2: Semantic Scorer (stub)            │   │
│  │ Planned: embedding-based detection    │   │
│  └──────────┬───────────────────────────┘   │
│  ┌──────────▼───────────────────────────┐   │
│  │ L3: Classifier (mock)                 │   │
│  │ Planned: DeBERTa / API-based          │   │
│  └──────────┬───────────────────────────┘   │
│  ┌──────────▼───────────────────────────┐   │
│  │ L4: Tool Firewall                     │   │
│  │ Allowlists, arg validation, exfil,    │   │
│  │ canary token detection                │   │
│  └──────────┬───────────────────────────┘   │
│  ┌──────────▼───────────────────────────┐   │
│  │ L5: Alignment Gate                    │   │
│  │ Intent-action mapping, approval gates │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
         │
    ScanResponse { risk_score, labels[], decision, trace[] }
```

## Component Map

| Component | Location | Responsibility |
|-----------|----------|----------------|
| **Gateway API** | `apps/gateway/app/` | HTTP endpoints, routing, request ID |
| **Scan Orchestrator** | `apps/gateway/app/services/scan_orchestrator.py` | 6-layer pipeline execution |
| **Enforce Service** | `apps/gateway/app/services/enforce_service.py` | Tool call policy evaluation |
| **L0 Normalizer** | `packages/core/normalization/normalizer.py` | Text canonicalization |
| **L1 Heuristics** | `packages/core/heuristics/` | Regex-based injection detection |
| **L2 Semantic** | `packages/core/semantics/scorer.py` | Stub (future: embedding scoring) |
| **L3 Classifier** | `packages/core/classifiers/classifier.py` | Mock (future: ML classifier) |
| **L4 Firewall** | `packages/core/toolfirewall/firewall.py` | Tool call security |
| **L5 Alignment** | `packages/core/alignment/gate.py` | Intent-action verification |
| **Policy Engine** | `packages/core/policy/` | YAML-backed tool policies |
| **Eval Runner** | `apps/evalrunner/` | Experiment execution & scoring |
| **Triage Engine** | `apps/evalrunner/triage.py` | FP/FN classification & analysis |
| **DuckDB Store** | `packages/core/storage/duckdb_store.py` | Result persistence |
| **Report Generator** | `apps/evalrunner/reporter.py` | Markdown/CSV reports |
| **Provider Adapters** | `apps/gateway/app/providers/` | OpenAI, Gemini, Azure OpenAI |

## Data Flow

### Scan Request
1. Client sends `POST /v1/scan` with `user_input`, `retrieved_context[]`, optional `draft_tool_call`
2. Orchestrator combines texts, runs L0→L1 (always), L2→L3 (conditional on L1 score)
3. If `draft_tool_call` present, runs L4→L5
4. Returns `ScanResponse` with aggregated `risk_score`, `labels[]`, `decision` (ALLOW/WARN/BLOCK)

### Enforce Request
1. Client sends `POST /v1/enforce` with `draft_tool_call`, `user_intent`, `trust_zone`
2. EnforceService evaluates via ToolFirewall + AlignmentGate
3. Returns `EnforceResponse` with `tool_policy_decision`, `reason`

### Eval Flow
1. Load scenarios from YAML (attack + benign sets)
2. For each scenario, send to `/v1/scan` and collect BLOCK/ALLOW decision
3. Score with ASR/FPR/Utility/Latency scorers
4. Store results in DuckDB, generate markdown report

## Defense Layers

### L0 — Normalization
- Unicode NFC normalization
- Base64 inline decode (replaces encoded segments with decoded text)
- URL-encoding inline decode (`%XX` → characters)
- Zero-width character stripping + spaced variant for L1 secondary scan
- Unicode homoglyph → Latin replacement
- Markdown system prompt injection normalization (`[system](#context)`)

### L1 — Heuristic Engine
- **105 rules** across 15 categories:
  - OVERRIDE, SECRET_EXTRACTION, ROLE_CONFUSION, INSTRUCTION_SMUGGLING
  - TOOL_ABUSE, INDIRECT_INJECTION, EXFILTRATION, ENCODING_EVASION
  - PERSONA_MARKERS, EXPLOITATION, LATENT_INJECTION
  - DENIED_REQUESTS, ACTION_OVERRIDE, CHAIN_COMMANDS, PRIVILEGE_ESCALATION
- Weighted scoring: cumulative rule weights
- Secondary scan pass on decoded segments from L0

### L2 — Semantic Scorer (Stub)
- Future: embedding similarity against known injection vectors

### L3 — Classifier (Mock)
- Future: ML model (DeBERTa / DistilBERT / OpenAI Guardrails API)

### L4 — Tool Firewall
- Tool allowlist/denylist from `policies/default_tools.yaml`
- Argument schema validation
- Exfiltration URL detection
- Canary token leak detection
- Chain depth limits

### L5 — Alignment Gate
- Intent-action mapping (user intent vs. proposed tool)
- Mandatory/bypass tool lists
- Human approval triggers for high-risk actions

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.13 |
| API Framework | FastAPI 0.135 |
| Server | Uvicorn 0.41 |
| Validation | Pydantic 2.12 |
| Storage | DuckDB 1.4 |
| Logging | structlog 25.5 |
| HTTP Client | httpx 0.28 |
| LLM SDKs | openai 2.26, google-genai 1.66 |
| Testing | pytest 9.0, pytest-asyncio |

## Key Design Decisions

1. **Evaluation-first**: Build the eval harness alongside defenses
2. **6-layer pipeline**: Defense-in-depth instead of single-model reliance
3. **Regex-only L1**: No API keys required for core scanning
4. **Conditional execution**: L2/L3 only triggered above L1 threshold
5. **Fail-closed**: Tool Firewall denies by default
6. **DuckDB for storage**: Embedded, fast analytics, no server needed
7. **Self-improvement loop**: Triage missed attacks → new rules → re-evaluate
