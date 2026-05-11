"""In-process per-tenant token-bucket rate limiter."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from pii_cleaner.config.settings import Settings, TenantRegistry
from pii_cleaner.errors import ErrorCode


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class TokenBucketLimiter:
    def __init__(self, registry: TenantRegistry, settings: Settings) -> None:
        self._registry = registry
        self._settings = settings
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}

    def _limits_for(self, tenant_id: str) -> tuple[int, int]:
        tenant = self._registry.get(tenant_id)
        rps = (
            tenant.rate_limit_rps
            if tenant and tenant.rate_limit_rps is not None
            else self._settings.default_rps
        )
        burst = (
            tenant.rate_limit_burst
            if tenant and tenant.rate_limit_burst is not None
            else self._settings.default_burst
        )
        return rps, burst

    def try_consume(self, tenant_id: str, cost: float = 1.0) -> tuple[bool, float, float]:
        """Returns (allowed, remaining, retry_after_seconds)."""
        rps, burst = self._limits_for(tenant_id)
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(tenant_id)
            if bucket is None:
                bucket = _Bucket(tokens=float(burst), last_refill=now)
                self._buckets[tenant_id] = bucket
            elapsed = max(0.0, now - bucket.last_refill)
            bucket.tokens = min(float(burst), bucket.tokens + elapsed * rps)
            bucket.last_refill = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, bucket.tokens, 0.0
            deficit = cost - bucket.tokens
            retry_after = deficit / rps if rps > 0 else math.inf
            return False, bucket.tokens, retry_after


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Callable[..., Awaitable[Response]],
        limiter: TokenBucketLimiter,
    ) -> None:
        super().__init__(app)
        self._limiter = limiter

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        tenant_id: str | None = getattr(request.state, "tenant_id", None)
        if tenant_id is None:
            return await call_next(request)

        allowed, remaining, retry_after = self._limiter.try_consume(tenant_id)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": ErrorCode.RATE_LIMITED.value,
                        "message": "Rate limit exceeded",
                        "request_id": getattr(request.state, "request_id", None),
                    }
                },
                headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(int(remaining))
        return response
