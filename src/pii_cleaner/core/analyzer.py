"""Presidio analyzer wrapper with lazy singleton lifecycle."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


@dataclass(frozen=True)
class DetectedEntity:
    type: str
    start: int
    end: int
    score: float


class AnalyzerHolder:
    """Holds the initialized Presidio engines; lazy-loaded to keep imports cheap."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._analyzer: AnalyzerEngine | None = None
        self._anonymizer: AnonymizerEngine | None = None

    def _ensure(self) -> tuple[AnalyzerEngine, AnonymizerEngine]:
        # Double-check: first guard is lock-free for the hot path; second prevents duplicate init.
        if self._analyzer is None:
            with self._lock:
                if self._analyzer is None:
                    self._analyzer = AnalyzerEngine()
                    self._anonymizer = AnonymizerEngine()
        assert self._analyzer is not None
        assert self._anonymizer is not None
        return self._analyzer, self._anonymizer

    def is_ready(self) -> bool:
        return self._analyzer is not None and self._anonymizer is not None

    def warm(self) -> None:
        self._ensure()

    def detect(self, text: str, entities: list[str]) -> list[DetectedEntity]:
        analyzer, _ = self._ensure()
        results = analyzer.analyze(text=text, entities=entities, language="en")
        return [
            DetectedEntity(type=r.entity_type, start=r.start, end=r.end, score=float(r.score))
            for r in results
        ]

    def redact(self, text: str, entities: list[DetectedEntity]) -> str:
        if not entities:
            return text
        _, anonymizer = self._ensure()
        operators = {
            e.type: OperatorConfig("replace", {"new_value": f"[{e.type}]"}) for e in entities
        }
        presidio_results = [
            RecognizerResult(entity_type=e.type, start=e.start, end=e.end, score=e.score)
            for e in entities
        ]
        result = anonymizer.anonymize(
            text=text,
            analyzer_results=presidio_results,
            operators=operators,
        )
        return str(result.text)


_holder: AnalyzerHolder | None = None
_holder_lock = threading.Lock()


def get_analyzer() -> AnalyzerHolder:
    global _holder
    if _holder is None:
        with _holder_lock:
            if _holder is None:
                _holder = AnalyzerHolder()
    return _holder
