"""Typed errors and global FastAPI exception handlers."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = structlog.get_logger(__name__)


class ErrorCode(StrEnum):
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    INVALID_POLICY = "INVALID_POLICY"
    INVALID_REQUEST = "INVALID_REQUEST"
    NOT_FOUND = "NOT_FOUND"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    RATE_LIMITED = "RATE_LIMITED"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class AppError(Exception):
    code: ErrorCode = ErrorCode.INTERNAL_ERROR
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class UnauthorizedError(AppError):
    code = ErrorCode.UNAUTHORIZED
    status_code = status.HTTP_401_UNAUTHORIZED


class InvalidPolicyError(AppError):
    code = ErrorCode.INVALID_POLICY
    status_code = status.HTTP_400_BAD_REQUEST


class PayloadTooLargeError(AppError):
    code = ErrorCode.PAYLOAD_TOO_LARGE
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


class RequestTimeoutError(AppError):
    code = ErrorCode.REQUEST_TIMEOUT
    status_code = status.HTTP_504_GATEWAY_TIMEOUT


def error_envelope(code: str, message: str, request_id: str | None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "request_id": request_id}}


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


async def app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)
    log = logger.error if exc.status_code >= 500 else logger.info
    log(
        "app_error",
        code=exc.code.value,
        status=exc.status_code,
        request_id=_request_id(request),
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=error_envelope(exc.code.value, exc.message, _request_id(request)),
    )


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    # Surface field paths (loc) but never values — values may be PII.
    locations = [".".join(str(p) for p in err.get("loc", ())) for err in exc.errors()]
    logger.info("validation_error", request_id=_request_id(request), fields=locations)
    message = f"Invalid request body: {locations[0]}" if locations else "Invalid request body"
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=error_envelope(
            ErrorCode.INVALID_REQUEST.value,
            message,
            _request_id(request),
        ),
    )


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = ErrorCode.INTERNAL_ERROR
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        code = ErrorCode.UNAUTHORIZED
    elif exc.status_code == status.HTTP_403_FORBIDDEN:
        code = ErrorCode.FORBIDDEN
    elif exc.status_code == status.HTTP_404_NOT_FOUND:
        code = ErrorCode.NOT_FOUND
    elif exc.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE:
        code = ErrorCode.UNSUPPORTED_MEDIA_TYPE
    elif exc.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE:
        code = ErrorCode.PAYLOAD_TOO_LARGE
    return JSONResponse(
        status_code=exc.status_code,
        content=error_envelope(code.value, str(exc.detail), _request_id(request)),
        headers=exc.headers,
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    from pii_cleaner.observability.metrics import analyzer_errors_total

    analyzer_errors_total.labels(kind="unhandled").inc()
    logger.error(
        "unhandled_error",
        error_type=type(exc).__name__,
        request_id=_request_id(request),
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_envelope(
            ErrorCode.INTERNAL_ERROR.value,
            "Internal server error",
            _request_id(request),
        ),
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
