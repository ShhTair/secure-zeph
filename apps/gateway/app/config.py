"""Gateway application configuration via Pydantic Settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- OpenAI ---
    openai_api_key: str = ""
    openai_org_id: str = ""
    openai_default_model: str = "gpt-4o"

    # --- Anthropic ---
    anthropic_api_key: str = ""
    anthropic_default_model: str = "claude-sonnet-4-20250514"

    # --- Google / Gemini ---
    google_api_key: str = ""
    gemini_default_model: str = "gemini-2.0-flash"

    # --- Azure OpenAI ---
    azure_openai_api_key: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_version: str = "2024-12-01-preview"
    azure_openai_deployment_name: str = ""

    # --- Azure Foundry ---
    azure_foundry_endpoint: str = ""
    azure_foundry_api_key: str = ""
    azure_foundry_deployment_name: str = ""

    # --- Storage ---
    duckdb_path: str = "data/results/experiments.duckdb"
    results_dir: str = "data/results"
    triage_dir: str = "triage"

    # --- Tracing ---
    log_level: str = "INFO"
    log_format: str = "json"
    trace_enabled: bool = True

    # --- Eval ---
    eval_concurrency: int = 5
    eval_timeout_seconds: int = 30
    eval_temperature: float = 0.0
    eval_max_tokens: int = 1024

    # --- Canary ---
    canary_token_secret: str = "CANARY-zeph-2026-XXXXXX"


def get_settings() -> Settings:
    return Settings()
