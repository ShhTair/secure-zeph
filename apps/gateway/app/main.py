"""Secure Zeph Gateway — FastAPI application."""

from fastapi import FastAPI

from apps.gateway.app.api import health, v1_scan, v1_enforce, v1_proxy
from apps.gateway.app.middleware.request_id import RequestIdMiddleware

app = FastAPI(
    title="Secure Zeph Gateway",
    description="Prompt-injection security middleware for agentic systems",
    version="0.1.0",
)

app.add_middleware(RequestIdMiddleware)

app.include_router(health.router, tags=["health"])
app.include_router(v1_scan.router, tags=["scan"])
app.include_router(v1_enforce.router, tags=["enforce"])
app.include_router(v1_proxy.router, tags=["proxy"])
