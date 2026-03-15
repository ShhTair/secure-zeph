"""Provider Adapter ABC — unified interface for all LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from packages.core.schemas.proxy_request import ProxyRequest, ProxyResponse


class ProviderAdapter(ABC):
    """Base class for all LLM provider adapters."""

    provider_name: str = "base"

    @abstractmethod
    async def complete(self, request: ProxyRequest) -> ProxyResponse:
        """Send a completion request to the provider."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the provider is accessible."""
        ...

    def is_configured(self) -> bool:
        """Check if provider has required credentials."""
        return False
