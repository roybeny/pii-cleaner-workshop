"""Orchestrates detection + redaction and produces the detection report."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from pii_cleaner.core.analyzer import AnalyzerHolder, DetectedEntity
from pii_cleaner.core.policy import ResolvedPolicy, threshold_for

# SECURITY: No try/except around Presidio calls below. A silent fallback that returns
# the original text on failure would leak every PII value in the payload. An analyzer
# exception MUST surface as a 5xx so the client retries or fails loud — never as a 200
# with unredacted content. See test_analyzer_failure_does_not_leak_pii.


@dataclass(frozen=True)
class CleanResult:
    cleaned_text: str
    entities: list[DetectedEntity]
    report: dict[str, int]


def clean_text(analyzer: AnalyzerHolder, text: str, policy: ResolvedPolicy) -> CleanResult:
    if not text:
        return CleanResult(cleaned_text=text, entities=[], report={})

    raw = analyzer.detect(text=text, entities=sorted(policy.entities))
    kept = [e for e in raw if e.score >= threshold_for(policy, e.type)]
    cleaned = analyzer.redact(text=text, entities=kept)
    report = dict(Counter(e.type for e in kept))
    return CleanResult(cleaned_text=cleaned, entities=kept, report=report)
