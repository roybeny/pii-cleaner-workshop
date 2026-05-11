from __future__ import annotations

import time
from pathlib import Path

from pii_cleaner.config.settings import Settings, TenantRegistry
from pii_cleaner.ratelimit.token_bucket import TokenBucketLimiter


def _limiter(tenants_file: Path, rps: int = 2, burst: int = 3) -> TokenBucketLimiter:
    registry = TenantRegistry(tenants_file)
    settings = Settings()
    settings_dict = settings.model_dump()
    settings_dict["default_rps"] = rps
    settings_dict["default_burst"] = burst
    return TokenBucketLimiter(registry, Settings(**settings_dict))


def test_consumes_tokens_and_rejects_when_empty(tenants_file: Path) -> None:
    limiter = _limiter(tenants_file)
    # Fixture sets acme to 1000rps/2000burst; use an unknown tenant to hit defaults.
    for _ in range(3):
        allowed, _, _ = limiter.try_consume("anon", cost=1.0)
        assert allowed
    allowed, _, retry = limiter.try_consume("anon", cost=1.0)
    assert not allowed
    assert retry > 0


def test_refills_over_time(tenants_file: Path) -> None:
    limiter = _limiter(tenants_file, rps=10, burst=1)
    allowed, _, _ = limiter.try_consume("anon", cost=1.0)
    assert allowed
    allowed, _, _ = limiter.try_consume("anon", cost=1.0)
    assert not allowed
    time.sleep(0.2)  # Should refill 2 tokens at 10 rps.
    allowed, _, _ = limiter.try_consume("anon", cost=1.0)
    assert allowed


def test_tenant_override_used_when_present(tenants_file: Path) -> None:
    limiter = _limiter(tenants_file, rps=1, burst=1)
    # Fixture gives tenant 'acme' rps=1000, burst=2000.
    for _ in range(10):
        allowed, _, _ = limiter.try_consume("acme", cost=1.0)
        assert allowed
