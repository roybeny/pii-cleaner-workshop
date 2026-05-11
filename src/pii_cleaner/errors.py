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
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    RATE_LIMITED = "RATE_LIMITED"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class AppError(Exception):
    code: ErrorCode = ErrorCode.INTERNAL_ERROR
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    headers: dict[str, str] | None = None

    def __init__(self, message: str, *, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        if headers is not None:
            self.headers = headers


class UnauthorizedError(AppError):
    code = ErrorCode.UNAUTHORIZED
    status_code = status.HTTP_401_UNAUTHORIZED


class ForbiddenError(AppError):
    code = ErrorCode.FORBIDDEN
    status_code = status.HTTP_403_FORBIDDEN


class InvalidPolicyError(AppError):
    code = ErrorCode.INVALID_POLICY
    status_code = status.HTTP_400_BAD_REQUEST


class InvalidRequestError(AppError):
    code = ErrorCode.INVALID_REQUEST
    status_code = status.HTTP_400_BAD_REQUEST


class PayloadTooLargeError(AppError):
    code = ErrorCode.PAYLOAD_TOO_LARGE
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


class RateLimitedError(AppError):
    code = ErrorCode.RATE_LIMITED
    status_code = status.HTTP_429_TOO_MANY_REQUESTS


class UnsupportedMediaTypeError(AppError):
    code = ErrorCode.UNSUPPORTED_MEDIA_TYPE
    status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE


class RequestTimeoutError(AppError):
    code = ErrorCode.REQUEST_TIMEOUT
    status_code = status.HTTP_504_GATEWAY_TIMEOUT


def _envelope(code: str, message: str, request_id: str | None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "request_id": request_id}}


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


async def app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)
    logger.info(
        "app_error",
        code=exc.code.value,
        status=exc.status_code,
        request_id=_request_id(request),
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=_envelope(exc.code.value, exc.message, _request_id(request)),
        headers=exc.headers,
    )


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    logger.info("validation_error", request_id=_request_id(request))
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=_envelope(
            ErrorCode.INVALID_REQUEST.value,
            "Invalid request body",
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
        code = ErrorCode.INVALID_REQUEST
    elif exc.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE:
        code = ErrorCode.UNSUPPORTED_MEDIA_TYPE
    elif exc.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE:
        code = ErrorCode.PAYLOAD_TOO_LARGE
    return JSONResponse(
        status_code=exc.status_code,
        content=_envelope(code.value, str(exc.detail), _request_id(request)),
        headers=exc.headers,
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "unhandled_error",
        error_type=type(exc).__name__,
        request_id=_request_id(request),
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_envelope(
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
