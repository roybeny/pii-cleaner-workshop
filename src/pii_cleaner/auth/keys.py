"""Argon2id-based tenant key verification."""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections import OrderedDict

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from pii_cleaner.config.settings import TenantRegistry

_hasher = PasswordHasher()
_CACHE_MAX = 1024


class KeyVerifier:
    """Verifies bearer tokens against the tenant registry."""

    def __init__(self, registry: TenantRegistry) -> None:
        self._registry = registry
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, str] = OrderedDict()

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
        """Return tenant_id if token is valid, else None. Iterates all tenants on failure."""
        if not token:
            return None
        fp = self._fingerprint(token)
        cached = self._cache_get(fp)
        if cached is not None:
            return cached

        matched_tenant: str | None = None
        # Iterate every (tenant, key) pair regardless of early match to flatten timing.
        for tenant in self._registry.all():
            for key in tenant.keys:
                try:
                    _hasher.verify(key.hash, token)
                    if matched_tenant is None:
                        matched_tenant = tenant.id
                except VerifyMismatchError:
                    continue
                except Exception:  # noqa: S112 - corrupt hash: skip silently
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
