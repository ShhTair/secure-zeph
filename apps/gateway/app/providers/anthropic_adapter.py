"""Anthropic (Claude) Provider Adapter."""

from __future__ import annotations

import time
import uuid

import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from apps.gateway.app.config import get_settings
from apps.gateway.app.providers.base import ProviderAdapter
from packages.core.schemas.proxy_request import ProxyRequest, ProxyResponse, TokenUsage

logger = structlog.get_logger()


class AnthropicAdapter(ProviderAdapter):
    provider_name = "anthropic"

    def __init__(self):
        settings = get_settings()
        self._api_key = settings.anthropic_api_key
        self._default_model = settings.anthropic_default_model
        self._client = None

    def _get_client(self):
        if self._client is None:
            import anthropic

            self._client = anthropic.AsyncAnthropic(api_key=self._api_key)
        return self._client

    def is_configured(self) -> bool:
        return bool(self._api_key and self._api_key != "sk-ant-PLACEHOLDER")

    async def health_check(self) -> bool:
        return self.is_configured()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(min=1, max=10),
        reraise=True,
    )
    async def complete(self, request: ProxyRequest) -> ProxyResponse:
        start = time.perf_counter()
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        model = request.model or self._default_model

        client = self._get_client()

        # Separate system message from conversation
        system_text = ""
        messages = []
        for m in request.messages:
            if m.role == "system":
                system_text += m.content + "\n"
            else:
                messages.append({"role": m.role, "content": m.content})

        # Anthropic requires at least one user message
        if not messages:
            messages = [{"role": "user", "content": ""}]

        kwargs: dict = {
            "model": model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if system_text.strip():
            kwargs["system"] = system_text.strip()

        response = await client.messages.create(**kwargs)

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Extract text from content blocks
        output_parts = []
        for block in response.content:
            if hasattr(block, "text"):
                output_parts.append(block.text)
        output = "\n".join(output_parts)

        usage = response.usage

        logger.info(
            "anthropic_complete",
            provider=self.provider_name,
            model=model,
            latency_ms=round(elapsed_ms, 2),
            tokens=usage.input_tokens + usage.output_tokens if usage else 0,
        )

        return ProxyResponse(
            request_id=request_id,
            provider=self.provider_name,
            model=model,
            output=output,
            latency_ms=round(elapsed_ms, 2),
            token_usage=TokenUsage(
                prompt_tokens=usage.input_tokens if usage else 0,
                completion_tokens=usage.output_tokens if usage else 0,
                total_tokens=(usage.input_tokens + usage.output_tokens) if usage else 0,
            ),
        )
