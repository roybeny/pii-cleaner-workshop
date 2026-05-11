from __future__ import annotations

import io
import json
import logging

from pii_cleaner.observability.audit import AuditLogger


def _collect_logs() -> tuple[logging.Handler, io.StringIO]:
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler, buffer


def test_chain_links_across_events() -> None:
    handler, buffer = _collect_logs()
    audit = AuditLogger(key=b"secret", handler=handler)

    audit.emit({"event": "a", "value": 1})
    audit.emit({"event": "b", "value": 2})

    lines = [line for line in buffer.getvalue().splitlines() if line]
    assert len(lines) == 2
    a = json.loads(lines[0])
    b = json.loads(lines[1])
    assert a["prev_hash"] == "0" * 64
    assert b["prev_hash"] == a["hash"]
    assert a["hash"] != b["hash"]


def test_tampering_event_detected_by_rechain() -> None:
    import hashlib
    import hmac

    handler, buffer = _collect_logs()
    audit = AuditLogger(key=b"key", handler=handler)
    audit.emit({"event": "one"})
    audit.emit({"event": "two"})

    lines = [json.loads(line) for line in buffer.getvalue().splitlines() if line]
    prev = "0" * 64
    for rec in lines:
        body = json.dumps(rec["event"], sort_keys=True, separators=(",", ":"))
        expected = hmac.new(b"key", (prev + body).encode("utf-8"), hashlib.sha256).hexdigest()
        assert rec["hash"] == expected
        prev = expected

    # Tamper: flip a byte in the second event and recompute; chain must break.
    lines[1]["event"]["event"] = "twoX"
    body = json.dumps(lines[1]["event"], sort_keys=True, separators=(",", ":"))
    bad = hmac.new(b"key", (lines[0]["hash"] + body).encode("utf-8"), hashlib.sha256).hexdigest()
    assert bad != lines[1]["hash"]
