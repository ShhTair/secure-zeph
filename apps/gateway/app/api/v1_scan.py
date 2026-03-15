"""POST /v1/scan — Scan input through defense pipeline."""

from fastapi import APIRouter, Request

from packages.core.schemas.scan_request import ScanRequest, ScanResponse
from apps.gateway.app.services.scan_orchestrator import ScanOrchestrator

router = APIRouter()

_orchestrator = ScanOrchestrator()


@router.post("/v1/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    return _orchestrator.scan(request)
