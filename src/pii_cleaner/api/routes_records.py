"""Structured-record cleaning endpoint (JSON; CSV/Parquet for future extension)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request

from pii_cleaner.api.schemas import (
    CleanRecordsRequest,
    CleanRecordsResponse,
    FieldAction,
)
from pii_cleaner.core.analyzer import get_analyzer
from pii_cleaner.core.cleaner import clean_text
from pii_cleaner.core.policy import resolve_policy
from pii_cleaner.errors import (
    PayloadTooLargeError,
    RequestTimeoutError,
    UnauthorizedError,
)
from pii_cleaner.observability.metrics import entities_detected_total, payload_bytes

router = APIRouter()


@router.post("/v1/clean/records", response_model=CleanRecordsResponse)
async def clean_records_endpoint(
    request: Request, body: CleanRecordsRequest
) -> CleanRecordsResponse:
    settings = request.app.state.settings
    raw = body.model_dump_json().encode("utf-8")
    if len(raw) > settings.max_records_bytes:
        raise PayloadTooLargeError(
            f"Records payload exceeds max size of {settings.max_records_bytes} bytes"
        )
    payload_bytes.labels(endpoint="/v1/clean/records", direction="in").observe(len(raw))

    tenant_id: str | None = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise UnauthorizedError("Tenant not resolved")

    registry = request.app.state.tenant_registry
    tenant = registry.get(tenant_id)
    if tenant is None:
        raise UnauthorizedError("Unknown tenant")

    policy = resolve_policy(tenant, body.policy, settings)
    analyzer = get_analyzer()

    def _run() -> tuple[list[dict[str, Any]], dict[str, int]]:
        out_records: list[dict[str, Any]] = []
        aggregate: dict[str, int] = {}
        for record in body.records:
            new_record: dict[str, Any] = {}
            for field, value in record.items():
                action = body.field_policy.get(field)
                effective = action.action if action else FieldAction.CLEAN
                if effective == FieldAction.DROP:
                    continue
                if effective == FieldAction.SKIP or not isinstance(value, str):
                    new_record[field] = value
                    continue
                result = clean_text(analyzer, value, policy)
                new_record[field] = result.cleaned_text
                for k, v in result.report.items():
                    aggregate[k] = aggregate.get(k, 0) + v
            out_records.append(new_record)
        return out_records, aggregate

    try:
        records, report = await asyncio.wait_for(
            asyncio.to_thread(_run), timeout=settings.request_timeout_seconds
        )
    except TimeoutError as exc:
        raise RequestTimeoutError("Cleaning timed out") from exc

    for entity_type, count in report.items():
        entities_detected_total.labels(type=entity_type, tenant=tenant_id).inc(count)

    request.state.entity_counts = report
    request_id = getattr(request.state, "request_id", None)
    response = CleanRecordsResponse(records=records, report=report, request_id=request_id)
    payload_bytes.labels(endpoint="/v1/clean/records", direction="out").observe(
        len(response.model_dump_json().encode("utf-8"))
    )
    return response
