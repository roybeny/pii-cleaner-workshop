"""Asserts that request payloads never appear in logged output."""

from __future__ import annotations

import io
import logging
from typing import Any

import httpx
import pytest


@pytest.fixture
def log_buffer() -> io.StringIO:
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    root.addHandler(handler)
    yield buffer
    root.removeHandler(handler)


async def test_pii_values_not_in_logs(
    app: Any, api_keys: tuple[str, str], log_buffer: io.StringIO
) -> None:
    secret_email = "jdoe+topsecret@example.com"
    secret_phone = "+1-555-0199"
    text = f"reach me at {secret_email} or call {secret_phone}"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post(
            "/v1/clean",
            headers={"Authorization": f"Bearer {api_keys[0]}"},
            json={"text": text},
        )
    assert r.status_code == 200

    logs = log_buffer.getvalue()
    assert secret_email not in logs
    assert secret_phone not in logs
    assert text not in logs
