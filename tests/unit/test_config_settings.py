"""Covers TenantRegistry reload behavior and the PII_* env-var contract."""

from __future__ import annotations

from pathlib import Path

import pytest
from argon2 import PasswordHasher

from pii_cleaner.config.settings import Settings, TenantRegistry


def _write_tenants(path: Path, ids: list[str]) -> None:
    hasher = PasswordHasher()
    lines = ["tenants:"]
    for tid in ids:
        lines.append(f"  - id: {tid}")
        lines.append("    keys:")
        lines.append(f'      - hash: "{hasher.hash(tid + "-key")}"')
    path.write_text("\n".join(lines) + "\n")


def test_reload_picks_up_new_tenants(tmp_path: Path) -> None:
    path = tmp_path / "tenants.yaml"
    _write_tenants(path, ["acme"])
    registry = TenantRegistry(path)
    assert {t.id for t in registry.all()} == {"acme"}

    _write_tenants(path, ["acme", "globex"])
    registry.reload()
    assert {t.id for t in registry.all()} == {"acme", "globex"}


def test_reload_with_missing_file_preserves_prior_state(tmp_path: Path) -> None:
    # A transiently missing tenants.yaml on SIGHUP (secret rotation, FS hiccup) must
    # NOT blank out the in-memory registry. Wiping it turns every request into a 401
    # with no correlated log signal — exactly the kind of silent failure that takes
    # hours to diagnose in production.
    path = tmp_path / "tenants.yaml"
    _write_tenants(path, ["acme"])
    registry = TenantRegistry(path)
    assert registry.get("acme") is not None

    path.unlink()
    registry.reload()
    assert registry.get("acme") is not None


def test_reload_with_malformed_yaml_preserves_prior_state(tmp_path: Path) -> None:
    path = tmp_path / "tenants.yaml"
    _write_tenants(path, ["acme"])
    registry = TenantRegistry(path)

    path.write_text("this: is: not: valid: yaml: [[[")
    registry.reload()
    assert registry.get("acme") is not None


def test_reload_invalidates_key_verifier_cache(tmp_path: Path) -> None:
    # Revoking a key requires: (a) remove it from tenants.yaml, (b) SIGHUP. If the
    # KeyVerifier cache isn't invalidated on reload, revoked tokens keep authenticating
    # for up to the LRU window. A test locks this in — see review finding "Top #3".
    from pii_cleaner.auth.keys import KeyVerifier

    key_one = "key-one-value"
    key_two = "key-two-value"
    hasher = PasswordHasher()
    path = tmp_path / "tenants.yaml"
    path.write_text(
        "tenants:\n"
        "  - id: acme\n"
        "    keys:\n"
        f'      - hash: "{hasher.hash(key_one)}"\n'
        f'      - hash: "{hasher.hash(key_two)}"\n'
    )
    registry = TenantRegistry(path)
    verifier = KeyVerifier(registry)
    assert verifier.verify(key_one) == "acme"  # primes the cache

    # Rotate: remove key_one from disk + SIGHUP reload. Cache must be invalidated so
    # the revoked token is rejected on the next call.
    path.write_text(
        "tenants:\n"
        "  - id: acme\n"
        "    keys:\n"
        f'      - hash: "{hasher.hash(key_two)}"\n'
    )
    registry.reload()
    assert verifier.verify(key_one) is None
    assert verifier.verify(key_two) == "acme"


def test_env_vars_map_to_settings_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    # The PII_ prefix + uppercase-field-name mapping is a load-bearing contract
    # documented in the README. Renaming env_prefix or a field would silently break it.
    monkeypatch.setenv("PII_DEFAULT_RPS", "7")
    monkeypatch.setenv("PII_MAX_TEXT_BYTES", "500")
    monkeypatch.setenv("PII_OTEL_ENABLED", "true")

    settings = Settings()
    assert settings.default_rps == 7
    assert settings.max_text_bytes == 500
    assert settings.otel_enabled is True
