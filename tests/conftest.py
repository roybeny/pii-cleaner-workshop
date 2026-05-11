"""Shared test fixtures. Heavy Presidio/spaCy deps are stubbed by default."""

from __future__ import annotations

import io
import logging
import re
import sys
import types
from collections.abc import Generator, Iterator
from pathlib import Path

import pytest


def _install_stub_presidio() -> None:
    """Install minimal presidio stubs so imports work without heavy deps in tests."""
    if "presidio_analyzer" in sys.modules:
        return

    pa = types.ModuleType("presidio_analyzer")

    class RecognizerResult:
        def __init__(self, entity_type: str, start: int, end: int, score: float) -> None:
            self.entity_type = entity_type
            self.start = start
            self.end = end
            self.score = score

    class AnalyzerEngine:
        def analyze(self, text: str, entities: list[str], language: str) -> list[RecognizerResult]:
            results: list[RecognizerResult] = []
            if "EMAIL_ADDRESS" in entities:
                for m in re.finditer(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
                    results.append(RecognizerResult("EMAIL_ADDRESS", m.start(), m.end(), 1.0))
            if "PHONE_NUMBER" in entities:
                for m in re.finditer(r"\+?\d[\d\-\s]{6,}\d", text):
                    results.append(RecognizerResult("PHONE_NUMBER", m.start(), m.end(), 0.9))
            if "PERSON" in entities:
                for m in re.finditer(r"\b(John Doe|Jane Roe)\b", text):
                    results.append(RecognizerResult("PERSON", m.start(), m.end(), 0.85))
            return results

    pa.AnalyzerEngine = AnalyzerEngine  # type: ignore[attr-defined]
    pa.RecognizerResult = RecognizerResult  # type: ignore[attr-defined]
    sys.modules["presidio_analyzer"] = pa

    pan = types.ModuleType("presidio_anonymizer")
    pan_entities = types.ModuleType("presidio_anonymizer.entities")

    class OperatorConfig:
        def __init__(self, operator_name: str, params: dict[str, str]) -> None:
            self.operator_name = operator_name
            self.params = params

    class _AnonResult:
        def __init__(self, text: str) -> None:
            self.text = text

    class AnonymizerEngine:
        def anonymize(
            self,
            text: str,
            analyzer_results: list[RecognizerResult],
            operators: dict[str, OperatorConfig],
        ) -> _AnonResult:
            spans = sorted(analyzer_results, key=lambda r: r.start, reverse=True)
            out = text
            for r in spans:
                op = operators.get(r.entity_type)
                replacement = (
                    op.params.get("new_value", f"[{r.entity_type}]") if op else f"[{r.entity_type}]"
                )
                out = out[: r.start] + replacement + out[r.end :]
            return _AnonResult(out)

    pan.AnonymizerEngine = AnonymizerEngine  # type: ignore[attr-defined]
    pan_entities.OperatorConfig = OperatorConfig  # type: ignore[attr-defined]
    sys.modules["presidio_anonymizer"] = pan
    sys.modules["presidio_anonymizer.entities"] = pan_entities


_install_stub_presidio()


@pytest.fixture(autouse=True)
def _reset_singletons() -> Iterator[None]:
    """Reset module-level singletons between tests."""
    import pii_cleaner.config.settings as cfg
    import pii_cleaner.core.analyzer as analyzer_mod
    import pii_cleaner.observability.audit as audit_mod

    cfg._settings = None
    analyzer_mod._holder = None
    audit_mod._audit = None
    yield
    cfg._settings = None
    analyzer_mod._holder = None
    audit_mod._audit = None


@pytest.fixture
def tenants_file(tmp_path: Path) -> Path:
    """Writes a tenants.yaml with two known API keys for tenant 'acme'."""
    from argon2 import PasswordHasher

    hasher = PasswordHasher()
    key1 = "acme-test-key-1"
    key2 = "acme-test-key-2"
    h1 = hasher.hash(key1)
    h2 = hasher.hash(key2)
    path = tmp_path / "tenants.yaml"
    path.write_text(
        "tenants:\n"
        "  - id: acme\n"
        "    keys:\n"
        f'      - hash: "{h1}"\n'
        f'      - hash: "{h2}"\n'
        "    rate_limit_rps: 1000\n"
        "    rate_limit_burst: 2000\n"
        "    policy:\n"
        "      entities: [EMAIL_ADDRESS, PHONE_NUMBER, PERSON]\n"
    )
    return path


@pytest.fixture
def api_keys() -> tuple[str, str]:
    return "acme-test-key-1", "acme-test-key-2"


@pytest.fixture
def app_settings(tenants_file: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    from pii_cleaner.config.settings import Settings

    monkeypatch.setenv("PII_TENANTS_FILE", str(tenants_file))
    return Settings()


@pytest.fixture
def app(app_settings: object) -> object:
    from pii_cleaner.main import create_app

    return create_app(app_settings)  # type: ignore[arg-type]


@pytest.fixture
def captured_logs() -> Generator[io.StringIO, None, None]:
    """Capture pii_cleaner logger output into a StringIO buffer."""
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield buffer
    finally:
        root.removeHandler(handler)
