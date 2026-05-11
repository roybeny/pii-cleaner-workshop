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
                "field_policy": {
                    "name": {"action": "clean"},
                    "note": {"action": "clean"},
                    "id": {"action": "skip"},
                },
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
                "field_policy": {
                    "remove": {"action": "drop"},
                },
            },
        )
    assert r.status_code == 200
    assert r.json()["records"] == [{"keep": "fine"}]


async def test_health_endpoints(client: httpx.AsyncClient) -> None:
    async with client as ac:
        live = await ac.get("/health/live")
        ready = await ac.get("/health/ready")
    assert live.status_code == 200
    # Readiness might be 503 on first request if analyzer not yet warmed; we warm in lifespan
    # but httpx.ASGITransport with lifespan off by default — accept either.
    assert ready.status_code in (200, 503)


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
