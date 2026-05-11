"""Audit logger with an HMAC-SHA256 chain for tamper-evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

_GENESIS = "0" * 64

_logger = structlog.get_logger(__name__)


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
        """Append one chained record.

        On write failure, the chain head is NOT advanced, and AuditWriteError is raised.
        Callers must decide whether to fail the request (compliance default) or degrade.
        """
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
            try:
                self._logger.info(json.dumps(record, sort_keys=True, separators=(",", ":")))
            except Exception as exc:
                _logger.error("audit_write_failed", exc_info=True)
                raise AuditWriteError(str(exc)) from exc
            self._prev_hash = digest


class AuditWriteError(RuntimeError):
    """Raised when an audit record could not be persisted."""


_audit: AuditLogger | None = None
_audit_lock = threading.Lock()


def init_audit(key: bytes) -> AuditLogger:
    global _audit
    with _audit_lock:
        _audit = AuditLogger(key)
    return _audit


def get_audit() -> AuditLogger | None:
    return _audit


def load_hmac_key(path: Path | None, *, require: bool = False) -> bytes:
    """Load HMAC key from file.

    If `path` is provided but unreadable/empty, raises — an operator who sets
    PII_AUDIT_HMAC_KEY_FILE expects it to be used, so silently falling back is
    the wrong default.

    If `path` is None:
      - `require=True` raises (use in production).
      - `require=False` returns an ephemeral key and logs a WARNING. The audit
        chain won't survive restart — acceptable only for development.
    """
    if path is not None:
        if not path.exists():
            raise FileNotFoundError(f"HMAC key file not found: {path}")
        data = path.read_bytes().strip()
        if not data:
            raise ValueError(f"HMAC key file {path} is empty")
        return data
    if require:
        raise RuntimeError(
            "audit_hmac_key_file is required (PII_REQUIRE_AUDIT_KEY=true) but was not set"
        )
    _logger.warning(
        "audit_hmac_key_ephemeral",
        reason="no audit_hmac_key_file configured; chain will not survive restart",
    )
    return secrets.token_bytes(32)
