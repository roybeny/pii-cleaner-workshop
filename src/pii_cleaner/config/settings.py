"""Application settings and tenant registry."""

from __future__ import annotations

import signal
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, Field, PositiveInt, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = structlog.get_logger(__name__)

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
    max_text_bytes: PositiveInt = 1_048_576
    max_records_bytes: PositiveInt = 10_485_760
    tenants_file: Path = Path("/etc/pii-cleaner/tenants.yaml")
    default_rps: PositiveInt = 100
    default_burst: PositiveInt = 200
    default_entities: tuple[str, ...] = DEFAULT_ENTITIES
    default_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    request_timeout_seconds: float = Field(default=10.0, gt=0.0)
    otel_enabled: bool = False
    otel_endpoint: str | None = None
    audit_hmac_key_file: Path | None = None
    # When True, refuse to start without a readable HMAC key file. Set PII_REQUIRE_AUDIT_KEY=true
    # in production; leave false in development.
    require_audit_key: bool = False


class PolicyConfig(BaseModel):
    entities: list[str] = Field(default_factory=lambda: list(DEFAULT_ENTITIES), min_length=1)
    thresholds: dict[str, float] = Field(default_factory=dict)

    @field_validator("entities")
    @classmethod
    def _uppercase_entities(cls, v: list[str]) -> list[str]:
        return [e.upper() for e in v]

    @field_validator("thresholds")
    @classmethod
    def _validate_thresholds(cls, v: dict[str, float]) -> dict[str, float]:
        for entity, score in v.items():
            if not 0.0 <= score <= 1.0:
                raise ValueError(f"threshold for {entity!r} must be in [0.0, 1.0], got {score}")
        return {k.upper(): v for k, v in v.items()}


class TenantKey(BaseModel):
    # Argon2 PHC-string format: $argon2<i|d|id>$v=<v>$m=<m>,t=<t>,p=<p>$<salt>$<hash>
    hash: str = Field(pattern=r"^\$argon2(id|i|d)\$")


class Tenant(BaseModel):
    id: str = Field(min_length=1)
    keys: list[TenantKey] = Field(min_length=1)
    rate_limit_rps: PositiveInt | None = None
    rate_limit_burst: PositiveInt | None = None
    policy: PolicyConfig = Field(default_factory=PolicyConfig)

    @model_validator(mode="after")
    def _policy_entities_supported(self) -> Tenant:
        unknown = set(self.policy.entities) - set(DEFAULT_ENTITIES)
        if unknown:
            raise ValueError(
                f"tenant {self.id!r} policy references unknown entities: {sorted(unknown)}"
            )
        return self


class TenantsFile(BaseModel):
    tenants: list[Tenant]


class TenantRegistry:
    """Thread-safe tenant registry with SIGHUP reload."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._by_id: dict[str, Tenant] = {}
        self._reload_listeners: list[Callable[[], None]] = []
        # Initial load: a missing file at boot is legitimate (dev without config),
        # but we log loudly so operators aren't left chasing a silent 401 storm.
        if not self._path.exists():
            logger.warning("tenants_file_missing_at_boot", path=str(self._path))
        else:
            self._load_from_disk()

    def register_reload_listener(self, listener: Callable[[], None]) -> None:
        """Callbacks invoked after every successful reload (e.g. KeyVerifier cache invalidation)."""
        self._reload_listeners.append(listener)

    def _load_from_disk(self) -> None:
        raw = yaml.safe_load(self._path.read_text()) or {}
        parsed = TenantsFile.model_validate(raw)
        with self._lock:
            self._by_id = {t.id: t for t in parsed.tenants}

    def reload(self) -> None:
        """Reload from disk, preserving prior state on any failure.

        A transiently missing file or a malformed YAML must not blank out
        the in-memory registry — that would turn every subsequent request
        into a 401 with no obvious signal.
        """
        try:
            if not self._path.exists():
                logger.error("tenants_file_missing_on_reload", path=str(self._path))
                return
            self._load_from_disk()
        except Exception:
            logger.error("tenants_reload_failed", path=str(self._path), exc_info=True)
            return

        with self._lock:
            count = len(self._by_id)
        logger.info("tenants_reloaded", count=count)
        for listener in self._reload_listeners:
            listener()

    def all(self) -> list[Tenant]:
        with self._lock:
            return list(self._by_id.values())

    def get(self, tenant_id: str) -> Tenant | None:
        with self._lock:
            return self._by_id.get(tenant_id)

    def install_sighup_handler(self) -> None:
        def _handle(_signum: int, _frame: Any) -> None:
            self.reload()

        try:
            signal.signal(signal.SIGHUP, _handle)
            logger.info("sighup_reload_enabled")
        except (ValueError, OSError, AttributeError) as exc:
            # Not running in main thread, or platform without SIGHUP (e.g. Windows).
            logger.info("sighup_reload_disabled", reason=type(exc).__name__)


_settings: Settings | None = None
_settings_lock = threading.Lock()


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        with _settings_lock:
            if _settings is None:
                _settings = Settings()
    return _settings
