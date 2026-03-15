"""Core Pydantic schemas — Scenario & Experiment definitions."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Scenario definition
# ---------------------------------------------------------------------------

class ScenarioDefinition(BaseModel):
    id: str
    category: str = ""
    user_input: str = ""
    system_prompt: str = ""  # system message for the model
    retrieved_context: list[str] = Field(default_factory=list)
    expected: str = ""  # "blocked" | "allowed" | expected output text
    tools: list[str] = Field(default_factory=list)
    trust_zone: str = "USER"
    attack_type: str = ""
    attacker_tools: list[str] = Field(default_factory=list)
    attacker_instruction: str = ""
    source: str = ""  # dataset origin: "injecagent", "tensortrust", "garak", ...
    difficulty: str = ""  # "easy" | "medium" | "hard"
    injection_position: str = ""  # "direct" | "indirect" | "context" | "tool_output"
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Single scenario result
# ---------------------------------------------------------------------------

class ScenarioResult(BaseModel):
    scenario_id: str
    provider: str
    model: str = ""
    defense_mode: str = "baseline"  # "baseline" | "defended"
    model_output: str = ""
    risk_score: float = 0.0
    decision: str = "ALLOW"
    labels: list[str] = Field(default_factory=list)
    scan_trace: list[dict[str, Any]] = Field(default_factory=list)
    scores: dict[str, float] = Field(default_factory=dict)
    latency_ms: float = 0.0
    triage_bucket: str = ""
    # --- multi-model eval fields ---
    injection_followed: bool | None = None  # did model follow the injection?
    judge_reasoning: str = ""  # why the judge decided this
    refusal_detected: bool | None = None  # did model refuse the request?
    token_usage_prompt: int = 0
    token_usage_completion: int = 0
    error: str = ""  # error message if call failed


# ---------------------------------------------------------------------------
# Model target (provider + model + optional config)
# ---------------------------------------------------------------------------

class ModelTarget(BaseModel):
    """A specific provider+model combo to evaluate."""
    provider: str  # "openai", "anthropic", "gemini", "azure_openai"
    model: str  # "gpt-4o", "claude-sonnet-4-20250514", "gemini-2.0-flash", ...
    display_name: str = ""  # human-friendly label
    temperature: float = 0.0
    max_tokens: int = 1024

    def label(self) -> str:
        return self.display_name or f"{self.provider}/{self.model}"


# ---------------------------------------------------------------------------
# Experiment config (extended for multi-model)
# ---------------------------------------------------------------------------

class ExperimentConfig(BaseModel):
    id: str
    name: str = ""
    scenarios_path: str = ""
    providers: list[str] = Field(default_factory=list)  # legacy single-provider
    models: list[ModelTarget] = Field(default_factory=list)  # multi-model targets
    defense_modes: list[str] = Field(default_factory=lambda: ["defended"])  # ["baseline", "defended"]
    defense_mode: str = "baseline"  # legacy compat
    temperature: float = 0.0
    max_tokens: int = 1024
    concurrency: int = 5
    judge_provider: str = ""  # provider for LLM judge (empty = heuristic judge)
    judge_model: str = ""  # model for LLM judge
    repeat_count: int = 1  # repeat each scenario N times (for variance)


# ---------------------------------------------------------------------------
# Comparative result across models
# ---------------------------------------------------------------------------

class ModelMetrics(BaseModel):
    """Aggregated metrics for one model in one defense mode."""
    provider: str
    model: str
    defense_mode: str
    total_scenarios: int = 0
    total_attacks: int = 0
    total_benign: int = 0
    asr: float = 0.0  # attack success rate
    fpr: float = 0.0  # false positive rate
    injection_follow_rate: float = 0.0  # % attacks where model followed injection
    refusal_rate: float = 0.0  # % attacks where model refused
    mean_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    total_tokens: int = 0
    error_count: int = 0


# ---------------------------------------------------------------------------
# Experiment run
# ---------------------------------------------------------------------------

class ExperimentRun(BaseModel):
    run_id: str
    config: ExperimentConfig
    start_time: str = ""
    end_time: str = ""
    results: list[ScenarioResult] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    model_metrics: list[ModelMetrics] = Field(default_factory=list)  # per-model breakdown
