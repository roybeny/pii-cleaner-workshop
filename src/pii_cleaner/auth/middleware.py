"""Authentication middleware: resolves tenant from Authorization header."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from pii_cleaner.auth.keys import KeyVerifier, extract_bearer_token
from pii_cleaner.errors import ErrorCode, error_envelope

_UNAUTHENTICATED_PATHS = frozenset(
    {"/health/live", "/health/ready", "/metrics", "/docs", "/redoc", "/openapi.json"}
)


def _unauthorized(request: Request, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content=error_envelope(
            ErrorCode.UNAUTHORIZED.value,
            message,
            getattr(request.state, "request_id", None),
        ),
    )


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Callable[..., Awaitable[Response]], verifier: KeyVerifier) -> None:
        super().__init__(app)
        self._verifier = verifier

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path in _UNAUTHENTICATED_PATHS:
            return await call_next(request)

        token = extract_bearer_token(request.headers.get("authorization"))
        if token is None:
            return _unauthorized(request, "Missing or malformed Authorization header")

        tenant_id = self._verifier.verify(token)
        if tenant_id is None:
            return _unauthorized(request, "Invalid credentials")

        request.state.tenant_id = tenant_id
        return await call_next(request)
