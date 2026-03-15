"""Structured JSON logger using structlog.

Provides a pre-configured logger that outputs JSON lines
with consistent fields: timestamp, level, request_id, layer, etc.
"""

from __future__ import annotations

import structlog

from apps.gateway.app.tracing.trace_context import get_current_trace


def configure_logging(log_level: str = "INFO", json_format: bool = True) -> None:
    """Configure structlog for the application."""
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        _inject_request_id,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _inject_request_id(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: dict,
) -> dict:
    """Auto-inject request_id from active TraceContext."""
    if "request_id" not in event_dict:
        trace = get_current_trace()
        if trace:
            event_dict["request_id"] = trace.request_id
    return event_dict


def get_logger(name: str = "secure_zeph") -> structlog.stdlib.BoundLogger:
    """Get a bound structured logger."""
    return structlog.get_logger(name)
