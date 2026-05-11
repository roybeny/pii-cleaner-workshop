"""Prometheus metrics."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from time import perf_counter

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

registry = CollectorRegistry()

requests_total = Counter(
    "pii_requests_total",
    "Total HTTP requests",
    labelnames=("endpoint", "tenant", "status"),
    registry=registry,
)
request_duration = Histogram(
    "pii_request_duration_seconds",
    "Request latency in seconds",
    labelnames=("endpoint", "tenant"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0),
    registry=registry,
)
entities_detected_total = Counter(
    "pii_entities_detected_total",
    "Entities detected by type",
    labelnames=("type", "tenant"),
    registry=registry,
)
payload_bytes = Histogram(
    "pii_payload_bytes",
    "Payload size in bytes",
    labelnames=("endpoint", "direction"),
    buckets=(256, 1024, 4096, 16_384, 65_536, 262_144, 1_048_576, 10_485_760),
    registry=registry,
)
ratelimit_rejections_total = Counter(
    "pii_ratelimit_rejections_total",
    "Rate-limit rejections",
    labelnames=("tenant",),
    registry=registry,
)
analyzer_errors_total = Counter(
    "pii_analyzer_errors_total",
    "Analyzer errors",
    labelnames=("kind",),
    registry=registry,
)


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path
        if path == "/metrics":
            return await call_next(request)
        started = perf_counter()
        response = await call_next(request)
        duration = perf_counter() - started
        tenant = getattr(request.state, "tenant_id", None) or "anonymous"
        endpoint = _route_pattern(request) or path
        requests_total.labels(endpoint=endpoint, tenant=tenant, status=response.status_code).inc()
        request_duration.labels(endpoint=endpoint, tenant=tenant).observe(duration)
        if response.status_code == 429:
            ratelimit_rejections_total.labels(tenant=tenant).inc()
        return response


def _route_pattern(request: Request) -> str | None:
    route = request.scope.get("route")
    if route is not None and hasattr(route, "path"):
        return str(route.path)
    return None


def metrics_response() -> Response:
    return Response(content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
