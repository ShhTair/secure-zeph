"""OpenAI Provider Adapter."""

from __future__ import annotations

import time
import uuid

import structlog
from openai import AsyncOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from apps.gateway.app.config import get_settings
from apps.gateway.app.providers.base import ProviderAdapter
from packages.core.schemas.proxy_request import (
    ProxyRequest,
    ProxyResponse,
    TokenUsage,
)

logger = structlog.get_logger()


class OpenAIAdapter(ProviderAdapter):
    provider_name = "openai"

    def __init__(self):
        settings = get_settings()
        self._api_key = settings.openai_api_key
        self._default_model = settings.openai_default_model
        self._client: AsyncOpenAI | None = None

    def _get_client(self) -> AsyncOpenAI:
        if self._client is None:
            self._client = AsyncOpenAI(api_key=self._api_key)
        return self._client

    def is_configured(self) -> bool:
        return bool(self._api_key and self._api_key != "sk-PLACEHOLDER")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10), reraise=True)
    async def complete(self, request: ProxyRequest) -> ProxyResponse:
        start = time.perf_counter()
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        model = request.model or self._default_model

        client = self._get_client()
        messages = [{"role": m.role, "content": m.content} for m in request.messages]

        response = await client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )

        elapsed_ms = (time.perf_counter() - start) * 1000
        choice = response.choices[0] if response.choices else None
        output = choice.message.content if choice and choice.message else ""
        usage = response.usage

        logger.info(
            "openai_complete",
            provider=self.provider_name,
            model=model,
            latency_ms=round(elapsed_ms, 2),
            tokens=usage.total_tokens if usage else 0,
        )

        return ProxyResponse(
            request_id=request_id,
            provider=self.provider_name,
            model=model,
            output=output or "",
            latency_ms=round(elapsed_ms, 2),
            token_usage=TokenUsage(
                prompt_tokens=usage.prompt_tokens if usage else 0,
                completion_tokens=usage.completion_tokens if usage else 0,
                total_tokens=usage.total_tokens if usage else 0,
            ),
        )

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            await client.models.list()
            return True
        except Exception:
            return False
