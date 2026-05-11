from __future__ import annotations

from pathlib import Path

import pytest

import pii_cleaner.auth.keys as keys_module
from pii_cleaner.auth.keys import KeyVerifier, extract_bearer_token
from pii_cleaner.config.settings import TenantRegistry


def test_extract_bearer_token_parses_scheme() -> None:
    assert extract_bearer_token("Bearer abc") == "abc"
    assert extract_bearer_token("bearer abc") == "abc"
    assert extract_bearer_token("Basic abc") is None
    assert extract_bearer_token(None) is None
    assert extract_bearer_token("") is None
    assert extract_bearer_token("Bearer ") is None


def test_verify_accepts_both_active_keys(tenants_file: Path, api_keys: tuple[str, str]) -> None:
    registry = TenantRegistry(tenants_file)
    verifier = KeyVerifier(registry)
    k1, k2 = api_keys
    assert verifier.verify(k1) == "acme"
    assert verifier.verify(k2) == "acme"


def test_verify_rejects_unknown_key(tenants_file: Path) -> None:
    registry = TenantRegistry(tenants_file)
    verifier = KeyVerifier(registry)
    assert verifier.verify("nope") is None


def test_cache_invalidation_clears_lookup(tenants_file: Path, api_keys: tuple[str, str]) -> None:
    registry = TenantRegistry(tenants_file)
    verifier = KeyVerifier(registry)
    assert verifier.verify(api_keys[0]) == "acme"
    verifier.invalidate()
    # Still works after invalidation (hits the registry again).
    assert verifier.verify(api_keys[0]) == "acme"


class _CountingHasher:
    """Wraps a real PasswordHasher and counts verify() calls."""

    def __init__(self, real: object) -> None:
        self._real = real
        self.calls = 0

    def verify(self, stored_hash: str, token: str) -> bool:
        self.calls += 1
        return self._real.verify(stored_hash, token)  # type: ignore[attr-defined]


def test_verify_iterates_all_keys_regardless_of_match(
    tenants_file: Path, api_keys: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Timing-flattening property: verify() iterates every (tenant, key) pair even
    # after finding a match. A short-circuit refactor would silently regress this.
    registry = TenantRegistry(tenants_file)
    verifier = KeyVerifier(registry)

    counting = _CountingHasher(keys_module._hasher)
    monkeypatch.setattr(keys_module, "_hasher", counting)

    # Fixture has exactly 2 keys for tenant 'acme'. Matching the first must still
    # try the second to keep total work constant regardless of which key matches.
    assert verifier.verify(api_keys[0]) == "acme"
    assert counting.calls == 2


def test_cache_hit_skips_argon2_verify(
    tenants_file: Path, api_keys: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Argon2id verify is ~100ms by design. Cache must prevent repeat verifies
    # for the same token, else the service has a silent perf cliff under load.
    registry = TenantRegistry(tenants_file)
    verifier = KeyVerifier(registry)

    counting = _CountingHasher(keys_module._hasher)
    monkeypatch.setattr(keys_module, "_hasher", counting)

    assert verifier.verify(api_keys[0]) == "acme"
    first_count = counting.calls
    assert first_count > 0

    assert verifier.verify(api_keys[0]) == "acme"
    # Cache hit: no additional argon2 verifies performed.
    assert counting.calls == first_count
