"""Google Gemini Provider Adapter."""

from __future__ import annotations

import time
import uuid

import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from apps.gateway.app.config import get_settings
from apps.gateway.app.providers.base import ProviderAdapter
from packages.core.schemas.proxy_request import ProxyRequest, ProxyResponse, TokenUsage

logger = structlog.get_logger()


class GeminiAdapter(ProviderAdapter):
    provider_name = "gemini"

    def __init__(self):
        settings = get_settings()
        self._api_key = settings.google_api_key
        self._default_model = settings.gemini_default_model
        self._client = None

    def _get_client(self):
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self._api_key)
        return self._client

    def is_configured(self) -> bool:
        return bool(self._api_key and self._api_key != "AIza-PLACEHOLDER")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10), reraise=True)
    async def complete(self, request: ProxyRequest) -> ProxyResponse:
        start = time.perf_counter()
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        model = request.model or self._default_model

        client = self._get_client()

        # Build contents from messages
        contents = []
        for m in request.messages:
            if m.role == "system":
                contents.append({"role": "user", "parts": [{"text": f"[System]: {m.content}"}]})
            elif m.role == "assistant":
                contents.append({"role": "model", "parts": [{"text": m.content}]})
            else:
                contents.append({"role": "user", "parts": [{"text": m.content}]})

        response = client.models.generate_content(
            model=model,
            contents=contents,
            config={
                "temperature": request.temperature,
                "max_output_tokens": request.max_tokens,
            },
        )

        elapsed_ms = (time.perf_counter() - start) * 1000
        output = response.text if response.text else ""
        usage_meta = getattr(response, "usage_metadata", None)

        logger.info(
            "gemini_complete",
            provider=self.provider_name,
            model=model,
            latency_ms=round(elapsed_ms, 2),
        )

        return ProxyResponse(
            request_id=request_id,
            provider=self.provider_name,
            model=model,
            output=output,
            latency_ms=round(elapsed_ms, 2),
            token_usage=TokenUsage(
                prompt_tokens=getattr(usage_meta, "prompt_token_count", 0) or 0,
                completion_tokens=getattr(usage_meta, "candidates_token_count", 0) or 0,
                total_tokens=getattr(usage_meta, "total_token_count", 0) or 0,
            ),
        )

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            client.models.list()
            return True
        except Exception:
            return False
