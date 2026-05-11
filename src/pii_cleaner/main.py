"""FastAPI app factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from pii_cleaner.api import routes_clean, routes_health, routes_records
from pii_cleaner.auth.keys import KeyVerifier
from pii_cleaner.auth.middleware import AuthMiddleware
from pii_cleaner.config.settings import Settings, TenantRegistry, get_settings
from pii_cleaner.core.analyzer import get_analyzer
from pii_cleaner.errors import register_error_handlers
from pii_cleaner.observability.audit import init_audit, load_hmac_key
from pii_cleaner.observability.logging import RequestContextMiddleware, configure_logging
from pii_cleaner.observability.metrics import MetricsMiddleware, metrics_response
from pii_cleaner.observability.tracing import configure_tracing
from pii_cleaner.ratelimit.token_bucket import RateLimitMiddleware, TokenBucketLimiter


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    analyzer = get_analyzer()
    analyzer.warm()
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    init_audit(load_hmac_key(settings.audit_hmac_key_file))

    app = FastAPI(
        title="PII Cleaner",
        version="0.1.0",
        lifespan=_lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    registry = TenantRegistry(settings.tenants_file)
    registry.install_sighup_handler()
    verifier = KeyVerifier(registry)
    limiter = TokenBucketLimiter(registry, settings)

    app.state.settings = settings
    app.state.tenant_registry = registry
    app.state.key_verifier = verifier
    app.state.rate_limiter = limiter

    register_error_handlers(app)

    # Middleware executes in reverse order of .add: first added = outermost.
    app.add_middleware(RateLimitMiddleware, limiter=limiter)
    app.add_middleware(AuthMiddleware, verifier=verifier)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(routes_health.router)
    app.include_router(routes_clean.router)
    app.include_router(routes_records.router)

    @app.get("/metrics", include_in_schema=False)
    async def _metrics() -> object:
        return metrics_response()

    configure_tracing(app, settings)
    return app


app = create_app()
