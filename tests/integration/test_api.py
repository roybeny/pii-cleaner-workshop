from __future__ import annotations

from typing import Any

import httpx
import pytest


@pytest.fixture
async def client(app: Any) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def test_clean_endpoint_redacts(client: httpx.AsyncClient, api_keys: tuple[str, str]) -> None:
    async with client as ac:
        r = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": "email me at john@acme.com"},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "john@acme.com" not in body["cleaned_text"]
    assert "[EMAIL_ADDRESS]" in body["cleaned_text"]
    assert body["report"] == {"EMAIL_ADDRESS": 1}
    assert body["request_id"] is not None
    # Values never appear in the entities list.
    for entity in body["entities"]:
        assert "value" not in entity


async def test_missing_auth_returns_401(client: httpx.AsyncClient) -> None:
    async with client as ac:
        r = await ac.post("/v1/clean", json={"text": "hi"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "UNAUTHORIZED"


async def test_invalid_token_returns_401(client: httpx.AsyncClient) -> None:
    async with client as ac:
        r = await ac.post(
            "/v1/clean",
            headers={"Authorization": "Bearer nope"},
            json={"text": "hi"},
        )
    assert r.status_code == 401


async def test_invalid_policy_returns_400(
    client: httpx.AsyncClient, api_keys: tuple[str, str]
) -> None:
    async with client as ac:
        r = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": "hi", "policy": {"entities": ["BOGUS"]}},
        )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_POLICY"


async def test_payload_too_large_returns_413(
    client: httpx.AsyncClient, api_keys: tuple[str, str], app: Any
) -> None:
    app.state.settings.max_text_bytes = 10
    async with client as ac:
        r = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": "this text is longer than ten bytes"},
        )
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


async def test_records_endpoint_cleans_per_field(
    client: httpx.AsyncClient, api_keys: tuple[str, str]
) -> None:
    async with client as ac:
        r = await ac.post(
            "/v1/clean/records",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={
                "records": [
                    {"name": "John Doe", "note": "email a@b.co", "id": 42},
                ],
                "field_policy": {"name": "clean", "note": "clean", "id": "skip"},
            },
        )
    assert r.status_code == 200, r.text
    body = r.json()
    record = body["records"][0]
    assert record["name"] == "[PERSON]"
    assert "a@b.co" not in record["note"]
    assert record["id"] == 42


async def test_records_endpoint_drops_fields(
    client: httpx.AsyncClient, api_keys: tuple[str, str]
) -> None:
    async with client as ac:
        r = await ac.post(
            "/v1/clean/records",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={
                "records": [{"keep": "fine", "remove": "gone"}],
                "field_policy": {"remove": "drop"},
            },
        )
    assert r.status_code == 200
    assert r.json()["records"] == [{"keep": "fine"}]


async def test_records_endpoint_rejects_nested_structures(
    client: httpx.AsyncClient, api_keys: tuple[str, str]
) -> None:
    # Nested record values are a PII-leak surface: the per-field loop only cleans
    # top-level strings. Schema must reject nested dicts/lists at parse time so a
    # caller sending {"user": {"email": "..."}} gets 400, not a silent pass-through.
    async with client as ac:
        r = await ac.post(
            "/v1/clean/records",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"records": [{"user": {"email": "a@b.co"}}]},
        )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


async def test_health_live_is_200_regardless_of_analyzer_state(
    client: httpx.AsyncClient,
) -> None:
    async with client as ac:
        live = await ac.get("/health/live")
    assert live.status_code == 200


async def test_health_ready_is_200_after_analyzer_is_warm(client: httpx.AsyncClient) -> None:
    # Warm the analyzer deterministically rather than depending on lifespan timing —
    # "accept either 200 or 503" is a meaningless assertion that masks a broken probe.
    from pii_cleaner.core.analyzer import get_analyzer

    get_analyzer().warm()
    async with client as ac:
        ready = await ac.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok", "analyzer": True}


async def test_metrics_endpoint_public(client: httpx.AsyncClient) -> None:
    async with client as ac:
        r = await ac.get("/metrics")
    assert r.status_code == 200
    assert "pii_requests_total" in r.text


async def test_rate_limit_headers(client: httpx.AsyncClient, api_keys: tuple[str, str]) -> None:
    async with client as ac:
        r = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": "hi"},
        )
    assert r.status_code == 200
    assert "x-ratelimit-remaining" in {k.lower() for k in r.headers}
    assert "x-request-id" in {k.lower() for k in r.headers}


async def test_unknown_tenant_after_auth_returns_401(
    client: httpx.AsyncClient, api_keys: tuple[str, str], app: Any
) -> None:
    # Auth succeeded (cached verifier) but the tenant was removed from the registry
    # between auth and route handler — e.g., mid-rotation SIGHUP reload. The route
    # must refuse rather than crash or serve a ghost tenant.
    async with client as ac:
        # Prime the verifier cache so auth will succeed without touching the registry.
        warm = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": "hi"},
        )
        assert warm.status_code == 200

        # Now remove the tenant. Cached auth still passes; route handler must 401.
        app.state.tenant_registry._by_id.clear()

        r = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": "hi"},
        )

    assert r.status_code == 401
    assert r.json()["error"]["code"] == "UNAUTHORIZED"


async def test_rate_limit_triggers_429_with_retry_after(
    client: httpx.AsyncClient, api_keys: tuple[str, str], app: Any
) -> None:
    # Force tight limits on tenant 'acme' and reset buckets so the next call fills it.
    tenant = app.state.tenant_registry.get("acme")
    tenant.rate_limit_rps = 1
    tenant.rate_limit_burst = 1
    app.state.rate_limiter._buckets.clear()

    async with client as ac:
        first = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": "hi"},
        )
        second = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": "hi"},
        )

    assert first.status_code == 200
    assert second.status_code == 429
    body = second.json()
    assert body["error"]["code"] == "RATE_LIMITED"
    assert "retry-after" in {k.lower() for k in second.headers}
    assert int(second.headers["retry-after"]) >= 1
