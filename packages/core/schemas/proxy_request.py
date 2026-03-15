"""Core Pydantic schemas — Proxy request/response."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Message(BaseModel):
    role: str
    content: str


class ProxyRequest(BaseModel):
    provider: str
    model: str = ""
    messages: list[Message] = Field(default_factory=list)
    defense_mode: bool = True
    temperature: float = 0.0
    max_tokens: int = 1024


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ProxyResponse(BaseModel):
    request_id: str
    provider: str
    model: str
    output: str = ""
    defense_trace: list[dict[str, Any]] = Field(default_factory=list)
    latency_ms: float = 0.0
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
