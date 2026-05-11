"""Text-cleaning endpoint."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request

from pii_cleaner.api.schemas import CleanRequest, CleanResponse, DetectedEntityOut
from pii_cleaner.core.analyzer import get_analyzer
from pii_cleaner.core.cleaner import CleanResult, clean_text
from pii_cleaner.core.policy import resolve_policy
from pii_cleaner.errors import (
    PayloadTooLargeError,
    RequestTimeoutError,
    UnauthorizedError,
)
from pii_cleaner.observability.metrics import entities_detected_total, payload_bytes

router = APIRouter()


@router.post("/v1/clean", response_model=CleanResponse)
async def clean_endpoint(request: Request, body: CleanRequest) -> CleanResponse:
    settings = request.app.state.settings
    encoded = body.text.encode("utf-8")
    if len(encoded) > settings.max_text_bytes:
        raise PayloadTooLargeError(f"Text exceeds max size of {settings.max_text_bytes} bytes")
    payload_bytes.labels(endpoint="/v1/clean", direction="in").observe(len(encoded))

    tenant_id: str | None = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise UnauthorizedError("Tenant not resolved")

    registry = request.app.state.tenant_registry
    tenant = registry.get(tenant_id)
    if tenant is None:
        raise UnauthorizedError("Unknown tenant")

    policy = resolve_policy(tenant, body.policy, settings)
    analyzer = get_analyzer()

    def _run() -> CleanResult:
        return clean_text(analyzer, body.text, policy)

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_run), timeout=settings.request_timeout_seconds
        )
    except TimeoutError as exc:
        raise RequestTimeoutError("Cleaning timed out") from exc

    for entity_type, count in result.report.items():
        entities_detected_total.labels(type=entity_type, tenant=tenant_id).inc(count)

    request.state.entity_counts = result.report
    request_id = getattr(request.state, "request_id", None)

    response = CleanResponse(
        cleaned_text=result.cleaned_text,
        entities=[
            DetectedEntityOut(type=e.type, start=e.start, end=e.end, score=e.score)
            for e in result.entities
        ],
        report=result.report,
        request_id=request_id,
    )
    payload_bytes.labels(endpoint="/v1/clean", direction="out").observe(
        len(response.model_dump_json().encode("utf-8"))
    )
    return response
