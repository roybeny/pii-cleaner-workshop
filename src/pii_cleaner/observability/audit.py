"""Audit logger with an HMAC-SHA256 chain for tamper-evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


class AuditLogger:
    """Emits one JSON line per request with an HMAC chain.

    Chain definition:
        hash_0     = HMAC(key, "GENESIS" || event_0_json)
        hash_{i+1} = HMAC(key, hash_i || event_{i+1}_json)

    Each emitted record contains {"prev_hash", "hash", "event": {...}}.
    """

    def __init__(self, key: bytes, handler: logging.Handler | None = None) -> None:
        self._key = key
        self._lock = threading.Lock()
        self._prev_hash = _GENESIS
        self._logger = logging.getLogger("pii_cleaner.audit")
        self._logger.propagate = False
        self._logger.setLevel(logging.INFO)
        # If a handler is supplied, replace existing handlers; otherwise install default once.
        if handler is not None:
            for existing in list(self._logger.handlers):
                self._logger.removeHandler(existing)
            self._logger.addHandler(handler)
        elif not self._logger.handlers:
            default = logging.StreamHandler(sys.stdout)
            default.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(default)

    def emit(self, event: dict[str, Any]) -> None:
        record_event = {
            "timestamp": datetime.now(UTC).isoformat(),
            **event,
        }
        with self._lock:
            body = json.dumps(record_event, sort_keys=True, separators=(",", ":"))
            digest = hmac.new(
                self._key, (self._prev_hash + body).encode("utf-8"), hashlib.sha256
            ).hexdigest()
            record = {"prev_hash": self._prev_hash, "hash": digest, "event": record_event}
            self._prev_hash = digest
            self._logger.info(json.dumps(record, sort_keys=True, separators=(",", ":")))


_audit: AuditLogger | None = None


def init_audit(key: bytes) -> AuditLogger:
    global _audit
    _audit = AuditLogger(key)
    return _audit


def get_audit() -> AuditLogger | None:
    return _audit


def load_hmac_key(path: Path | None) -> bytes:
    """Load HMAC key from file; fall back to a random dev key (not for prod)."""
    if path is not None and path.exists():
        data = path.read_bytes().strip()
        if not data:
            raise ValueError(f"HMAC key file {path} is empty")
        return data
    # Dev fallback: ephemeral key. Logs won't be verifiable across restarts.
    import secrets

    return secrets.token_bytes(32)
