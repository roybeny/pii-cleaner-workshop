"""Pydantic request/response models."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pii_cleaner.config.settings import PolicyConfig

# Flat scalar record values. Nested structures would bypass cleaning because the
# per-field loop only inspects top-level values — explicitly rejecting them here
# closes a PII-leak surface rather than silently passing nested strings through.
RecordValue = str | int | float | bool | None
Record = dict[str, RecordValue]


class CleanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., description="Text to clean.", max_length=10_000_000)
    policy: PolicyConfig | None = Field(
        default=None,
        description="Optional per-request policy override.",
    )


class DetectedEntityOut(BaseModel):
    type: str
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    score: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_span(self) -> DetectedEntityOut:
        if self.end <= self.start:
            raise ValueError("entity span end must be greater than start")
        return self


EntityCount = Annotated[int, Field(ge=0)]


class CleanResponse(BaseModel):
    cleaned_text: str
    entities: list[DetectedEntityOut]
    report: dict[str, EntityCount]
    request_id: str | None = None


class FieldAction(StrEnum):
    CLEAN = "clean"
    SKIP = "skip"
    DROP = "drop"


class CleanRecordsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[Record] = Field(max_length=10_000)
    field_policy: dict[str, FieldAction] = Field(default_factory=dict)
    policy: PolicyConfig | None = None


class CleanRecordsResponse(BaseModel):
    records: list[Record]
    report: dict[str, EntityCount]
    request_id: str | None = None
