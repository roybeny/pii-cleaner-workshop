from __future__ import annotations

from pathlib import Path

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
