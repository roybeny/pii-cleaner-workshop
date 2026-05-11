"""Application settings and tenant registry."""

from __future__ import annotations

import signal
import threading
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_ENTITIES: tuple[str, ...] = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "URL",
    "US_SSN",
    "PERSON",
    "LOCATION",
    "DATE_TIME",
    "NRP",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PII_", env_file=None, extra="ignore")

    log_level: str = "INFO"
    max_text_bytes: int = 1_048_576
    max_records_bytes: int = 10_485_760
    tenants_file: Path = Path("/etc/pii-cleaner/tenants.yaml")
    default_rps: int = 100
    default_burst: int = 200
    default_entities: tuple[str, ...] = DEFAULT_ENTITIES
    default_threshold: float = 0.5
    request_timeout_seconds: float = 10.0
    otel_enabled: bool = False
    otel_endpoint: str | None = None
    audit_hmac_key_file: Path | None = None


class PolicyConfig(BaseModel):
    entities: list[str] = Field(default_factory=lambda: list(DEFAULT_ENTITIES))
    thresholds: dict[str, float] = Field(default_factory=dict)

    @field_validator("entities")
    @classmethod
    def _uppercase_entities(cls, v: list[str]) -> list[str]:
        return [e.upper() for e in v]


class TenantKey(BaseModel):
    hash: str


class Tenant(BaseModel):
    id: str
    keys: list[TenantKey]
    rate_limit_rps: int | None = None
    rate_limit_burst: int | None = None
    policy: PolicyConfig = Field(default_factory=PolicyConfig)


class TenantsFile(BaseModel):
    tenants: list[Tenant]


class TenantRegistry:
    """Thread-safe tenant registry with SIGHUP reload."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._by_id: dict[str, Tenant] = {}
        self.reload()

    def reload(self) -> None:
        if not self._path.exists():
            with self._lock:
                self._by_id = {}
            return
        raw = yaml.safe_load(self._path.read_text()) or {}
        parsed = TenantsFile.model_validate(raw)
        with self._lock:
            self._by_id = {t.id: t for t in parsed.tenants}

    def all(self) -> list[Tenant]:
        with self._lock:
            return list(self._by_id.values())

    def get(self, tenant_id: str) -> Tenant | None:
        with self._lock:
            return self._by_id.get(tenant_id)

    def install_sighup_handler(self) -> None:
        import contextlib

        def _handle(_signum: int, _frame: Any) -> None:
            self.reload()

        # Not running in main thread or platform without SIGHUP; skip silently.
        with contextlib.suppress(ValueError, OSError, AttributeError):
            signal.signal(signal.SIGHUP, _handle)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
