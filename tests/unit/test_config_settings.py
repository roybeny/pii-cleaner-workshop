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


def test_reload_with_missing_file_clears_registry(tmp_path: Path) -> None:
    path = tmp_path / "tenants.yaml"
    _write_tenants(path, ["acme"])
    registry = TenantRegistry(path)
    assert registry.get("acme") is not None

    path.unlink()
    registry.reload()
    assert registry.all() == []
    assert registry.get("acme") is None


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
