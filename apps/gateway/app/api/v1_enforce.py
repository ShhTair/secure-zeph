"""POST /v1/enforce — Evaluate tool call against policy + alignment gate."""

from fastapi import APIRouter

from packages.core.schemas.enforce_request import EnforceRequest, EnforceResponse
from apps.gateway.app.services.enforce_service import EnforceService

router = APIRouter()

_service = EnforceService()


@router.post("/v1/enforce", response_model=EnforceResponse)
async def enforce(request: EnforceRequest):
    return _service.evaluate(request)
