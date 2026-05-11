"""Liveness and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from pii_cleaner.core.analyzer import get_analyzer

router = APIRouter()


@router.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
async def ready(response: Response) -> dict[str, object]:
    analyzer = get_analyzer()
    if not analyzer.is_ready():
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "analyzer": False}
    return {"status": "ok", "analyzer": True}
