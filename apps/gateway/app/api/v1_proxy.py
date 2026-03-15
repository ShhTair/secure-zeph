"""POST /v1/proxy — Proxy request to LLM provider with optional defense."""

from __future__ import annotations

import time
import uuid

from fastapi import APIRouter, HTTPException

from apps.gateway.app.providers import create_default_registry
from apps.gateway.app.services.scan_orchestrator import ScanOrchestrator
from packages.core.schemas.proxy_request import ProxyRequest, ProxyResponse
from packages.core.schemas.scan_request import Decision, ScanRequest

router = APIRouter()

_registry = create_default_registry()
_orchestrator = ScanOrchestrator()


@router.post("/v1/proxy", response_model=ProxyResponse)
async def proxy(request: ProxyRequest):
    """Proxy request to LLM provider, optionally scanning input first."""
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    start = time.perf_counter()
    defense_trace: list[dict] = []

    # --- optional defense scan ---
    if request.defense_mode and request.messages:
        user_text = " ".join(m.content for m in request.messages if m.role == "user")
        if user_text.strip():
            scan_req = ScanRequest(user_input=user_text)
            scan_resp = _orchestrator.scan(scan_req)
            defense_trace = [e.model_dump() for e in scan_resp.trace]

            if scan_resp.decision == Decision.BLOCK:
                return ProxyResponse(
                    request_id=request_id,
                    provider=request.provider,
                    model=request.model or "unknown",
                    output=f"[BLOCKED by defense pipeline] risk={scan_resp.risk_score:.2f} labels={scan_resp.labels}",
                    defense_trace=defense_trace,
                    latency_ms=round((time.perf_counter() - start) * 1000, 2),
                )

    # --- provider lookup ---
    adapter = _registry.get(request.provider)
    if adapter is None:
        available = _registry.list_all()
        raise HTTPException(status_code=400, detail=f"Unknown provider '{request.provider}'. Available: {available}")

    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail=f"Provider '{request.provider}' not configured (missing API key)")

    # --- call provider ---
    response = await adapter.complete(request)
    total_ms = round((time.perf_counter() - start) * 1000, 2)

    response.request_id = request_id
    response.defense_trace = defense_trace
    response.latency_ms = total_ms
    return response
