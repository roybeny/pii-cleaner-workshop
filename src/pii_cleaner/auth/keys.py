"""Argon2id-based tenant key verification."""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections import OrderedDict

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from pii_cleaner.config.settings import TenantRegistry

logger = structlog.get_logger(__name__)

_hasher = PasswordHasher()
_CACHE_MAX = 1024


class KeyVerifier:
    """Verifies bearer tokens against the tenant registry.

    Security invariants:
    - Always iterates every (tenant, key) pair — even after a match — to flatten
      timing and prevent tenant-existence enumeration via response time.
    - Caches successful verifications keyed by a SHA256 fingerprint of the token,
      so the raw bearer is never retained in process memory past verification.
    - Corrupt-hash entries in tenants.yaml log a WARNING (once per verify call)
      but must not take down auth for other tenants.
    """

    def __init__(self, registry: TenantRegistry) -> None:
        self._registry = registry
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, str] = OrderedDict()
        registry.register_reload_listener(self.invalidate)

    @staticmethod
    def _fingerprint(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _cache_get(self, fp: str) -> str | None:
        with self._lock:
            tenant_id = self._cache.get(fp)
            if tenant_id is not None:
                self._cache.move_to_end(fp)
            return tenant_id

    def _cache_put(self, fp: str, tenant_id: str) -> None:
        with self._lock:
            self._cache[fp] = tenant_id
            self._cache.move_to_end(fp)
            while len(self._cache) > _CACHE_MAX:
                self._cache.popitem(last=False)

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()

    def verify(self, token: str) -> str | None:
        """Return tenant_id if token is valid, else None."""
        if not token:
            return None
        fp = self._fingerprint(token)
        cached = self._cache_get(fp)
        if cached is not None:
            return cached

        matched_tenant: str | None = None
        for tenant in self._registry.all():
            for idx, key in enumerate(tenant.keys):
                try:
                    _hasher.verify(key.hash, token)
                    if matched_tenant is None:
                        matched_tenant = tenant.id
                except VerifyMismatchError:
                    continue
                except (InvalidHashError, VerificationError) as exc:
                    logger.warning(
                        "corrupt_tenant_hash",
                        tenant_id=tenant.id,
                        key_index=idx,
                        error_type=type(exc).__name__,
                    )
                    continue

        if matched_tenant is not None:
            self._cache_put(fp, matched_tenant)
            return matched_tenant
        return None


def extract_bearer_token(header_value: str | None) -> str | None:
    if not header_value:
        return None
    parts = header_value.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts
    if not hmac.compare_digest(scheme.lower(), "bearer"):
        return None
    return token.strip() or None
