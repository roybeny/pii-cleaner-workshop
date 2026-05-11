"""Structured logging with a PII-blocking processor."""

from __future__ import annotations

import asyncio
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

from pii_cleaner.observability.audit import get_audit

# SECURITY: every entry here is load-bearing. The processor below rewrites these
# keys to "<redacted>" rather than dropping them so callers notice the redaction
# rather than silently miss context. Adding an entry must be paired with a test in
# test_no_pii_in_logs.py; removing one requires a security review.
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


def _redact_pii_fields(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Recursively rewrite forbidden-field values to '<redacted>' at any nesting depth."""

    def _walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: ("<redacted>" if k in FORBIDDEN_LOG_FIELDS else _walk(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [_walk(v) for v in value]
        return value

    return {
        k: ("<redacted>" if k in FORBIDDEN_LOG_FIELDS else _walk(v)) for k, v in event_dict.items()
    }


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
            _redact_pii_fields,
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
    """Assigns a request id, logs request outcome, measures latency, emits audit."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("x-request-id") or str(ULID())
        request.state.request_id = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        started = perf_counter()
        status_code = 500
        disconnected = False
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-Id"] = request_id
            return response
        except asyncio.CancelledError:
            disconnected = True
            raise
        finally:
            latency_ms = round((perf_counter() - started) * 1000, 2)
            tenant_id = getattr(request.state, "tenant_id", None)
            entity_counts = getattr(request.state, "entity_counts", None)
            client_ip = request.client.host if request.client else None

            if disconnected:
                logger.info(
                    "client_disconnected",
                    method=request.method,
                    path=request.url.path,
                    latency_ms=latency_ms,
                    tenant_id=tenant_id,
                )
            else:
                log_method = logger.info if status_code < 500 else logger.error
                log_method(
                    "http_request",
                    method=request.method,
                    path=request.url.path,
                    status=status_code,
                    latency_ms=latency_ms,
                    tenant_id=tenant_id,
                    entity_counts=entity_counts,
                    client_ip=client_ip,
                )
                _emit_audit_event(
                    request_id=request_id,
                    tenant_id=tenant_id,
                    method=request.method,
                    path=request.url.path,
                    status=status_code,
                    entity_counts=entity_counts,
                    latency_ms=latency_ms,
                    client_ip=client_ip,
                )


def _emit_audit_event(
    *,
    request_id: str,
    tenant_id: str | None,
    method: str,
    path: str,
    status: int,
    entity_counts: dict[str, int] | None,
    latency_ms: float,
    client_ip: str | None,
) -> None:
    """Write one audit record per request. Failures are logged but do not break the response.

    Rationale: emission runs in a `finally` block after the response has already been sent;
    we cannot retroactively fail the request here. Operators who need fail-closed should add
    a readiness probe on the audit sink and alert on `audit_write_failed` log events.
    """
    audit = get_audit()
    if audit is None:
        return
    try:
        audit.emit(
            {
                "request_id": request_id,
                "tenant_id": tenant_id,
                "method": method,
                "path": path,
                "status": status,
                "entity_counts": entity_counts,
                "latency_ms": latency_ms,
                "client_ip": client_ip,
            }
        )
    except Exception:
        logger.error("audit_emit_failed", request_id=request_id, exc_info=True)
