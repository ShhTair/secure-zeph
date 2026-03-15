"""Provider Registry — register, discover, and retrieve provider adapters."""

from __future__ import annotations

from apps.gateway.app.providers.base import ProviderAdapter
from apps.gateway.app.providers.openai_adapter import OpenAIAdapter
from apps.gateway.app.providers.gemini_adapter import GeminiAdapter
from apps.gateway.app.providers.azure_openai_adapter import AzureOpenAIAdapter
from apps.gateway.app.providers.anthropic_adapter import AnthropicAdapter


class ProviderRegistry:
    def __init__(self):
        self._adapters: dict[str, ProviderAdapter] = {}

    def register(self, adapter: ProviderAdapter) -> None:
        self._adapters[adapter.provider_name] = adapter

    def get(self, name: str) -> ProviderAdapter | None:
        return self._adapters.get(name)

    def list_available(self) -> list[str]:
        return [name for name, adapter in self._adapters.items() if adapter.is_configured()]

    def list_all(self) -> list[str]:
        return list(self._adapters.keys())


def create_default_registry() -> ProviderRegistry:
    """Create registry with all Day 1 providers."""
    registry = ProviderRegistry()
    registry.register(OpenAIAdapter())
    registry.register(GeminiAdapter())
    registry.register(AzureOpenAIAdapter())
    registry.register(AnthropicAdapter())
    return registry
