"""Pydantic request/response models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from pii_cleaner.config.settings import PolicyConfig


class CleanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., description="Text to clean.")
    policy: PolicyConfig | None = Field(
        default=None,
        description="Optional per-request policy override.",
    )


class DetectedEntityOut(BaseModel):
    type: str
    start: int
    end: int
    score: float


class CleanResponse(BaseModel):
    cleaned_text: str
    entities: list[DetectedEntityOut]
    report: dict[str, int]
    request_id: str | None = None


class FieldAction(StrEnum):
    CLEAN = "clean"
    SKIP = "skip"
    DROP = "drop"


class FieldPolicyEntry(BaseModel):
    action: FieldAction = FieldAction.CLEAN


class CleanRecordsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[dict[str, Any]]
    field_policy: dict[str, FieldPolicyEntry] = Field(default_factory=dict)
    policy: PolicyConfig | None = None


class CleanRecordsResponse(BaseModel):
    records: list[dict[str, Any]]
    report: dict[str, int]
    request_id: str | None = None
