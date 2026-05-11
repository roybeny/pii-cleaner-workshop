"""Orchestrates detection + redaction and produces the detection report."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from pii_cleaner.core.analyzer import AnalyzerHolder, DetectedEntity
from pii_cleaner.core.policy import ResolvedPolicy, threshold_for


@dataclass(frozen=True)
class CleanResult:
    cleaned_text: str
    entities: list[DetectedEntity]
    report: dict[str, int]


def clean_text(analyzer: AnalyzerHolder, text: str, policy: ResolvedPolicy) -> CleanResult:
    if not text or not policy.entities:
        return CleanResult(cleaned_text=text, entities=[], report={})

    raw = analyzer.detect(text=text, entities=sorted(policy.entities))
    kept = [e for e in raw if e.score >= threshold_for(policy, e.type)]
    cleaned = analyzer.redact(text=text, entities=kept)
    report = dict(Counter(e.type for e in kept))
    return CleanResult(cleaned_text=cleaned, entities=kept, report=report)
