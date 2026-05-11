from __future__ import annotations

from pii_cleaner.config.settings import PolicyConfig, Settings, Tenant, TenantKey
from pii_cleaner.core.analyzer import get_analyzer
from pii_cleaner.core.cleaner import clean_text
from pii_cleaner.core.policy import resolve_policy


def _policy(entities: list[str]) -> object:
    tenant = Tenant(id="t", keys=[TenantKey(hash="x")], policy=PolicyConfig(entities=entities))
    return resolve_policy(tenant, None, Settings())


def test_redacts_email_and_phone() -> None:
    policy = _policy(["EMAIL_ADDRESS", "PHONE_NUMBER"])
    result = clean_text(get_analyzer(), "contact john@acme.com or +1-555-0100", policy)
    assert "john@acme.com" not in result.cleaned_text
    assert "[EMAIL_ADDRESS]" in result.cleaned_text
    assert "[PHONE_NUMBER]" in result.cleaned_text
    assert result.report == {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1}


def test_empty_input_returns_empty_report() -> None:
    policy = _policy(["EMAIL_ADDRESS"])
    result = clean_text(get_analyzer(), "", policy)
    assert result.cleaned_text == ""
    assert result.report == {}


def test_no_active_entities_is_noop() -> None:
    tenant = Tenant(id="t", keys=[TenantKey(hash="x")], policy=PolicyConfig(entities=[]))
    policy = resolve_policy(tenant, None, Settings())
    result = clean_text(get_analyzer(), "email a@b.co", policy)
    assert result.cleaned_text == "email a@b.co"
    assert result.report == {}


def test_threshold_filters_low_score_entities() -> None:
    tenant = Tenant(
        id="t",
        keys=[TenantKey(hash="x")],
        policy=PolicyConfig(entities=["PERSON"], thresholds={"PERSON": 0.99}),
    )
    policy = resolve_policy(tenant, None, Settings())
    result = clean_text(get_analyzer(), "Hello John Doe", policy)
    # Stub detects PERSON with score 0.85, below threshold 0.99.
    assert result.cleaned_text == "Hello John Doe"
    assert result.report == {}


def test_offsets_refer_to_original_text() -> None:
    policy = _policy(["EMAIL_ADDRESS"])
    text = "send to a@b.co please"
    result = clean_text(get_analyzer(), text, policy)
    assert len(result.entities) == 1
    e = result.entities[0]
    assert text[e.start : e.end] == "a@b.co"
