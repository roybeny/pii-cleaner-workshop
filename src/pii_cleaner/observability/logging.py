"""Structured logging with a PII-blocking processor."""

from __future__ import annotations

import logging
import sys
from collections.abc import Awaitable, Callable
from time import perf_counter
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from ulid import ULID

# Field names that are never allowed in log records. A structlog processor drops them.
FORBIDDEN_LOG_FIELDS = frozenset(
    {
        "text",
        "cleaned_text",
        "input",
        "output",
        "records",
        "record",
        "field_value",
        "value",
        "values",
        "body",
        "payload",
    }
)


def _block_pii_fields(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key in list(event_dict.keys()):
        if key in FORBIDDEN_LOG_FIELDS:
            event_dict[key] = "<redacted>"
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _block_pii_fields,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


logger = structlog.get_logger("pii_cleaner")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id, logs request outcome, measures latency."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("x-request-id") or str(ULID())
        request.state.request_id = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        started = perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-Id"] = request_id
            return response
        finally:
            latency_ms = round((perf_counter() - started) * 1000, 2)
            tenant_id = getattr(request.state, "tenant_id", None)
            entity_counts = getattr(request.state, "entity_counts", None)
            log_method = logger.info if status_code < 500 else logger.error
            log_method(
                "http_request",
                method=request.method,
                path=request.url.path,
                status=status_code,
                latency_ms=latency_ms,
                tenant_id=tenant_id,
                entity_counts=entity_counts,
                client_ip=request.client.host if request.client else None,
            )
