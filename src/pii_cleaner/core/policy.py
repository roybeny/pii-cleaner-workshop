"""Policy resolution: tenant default overlaid with per-request override."""

from __future__ import annotations

from dataclasses import dataclass

from pii_cleaner.config.settings import PolicyConfig, Settings, Tenant
from pii_cleaner.errors import InvalidPolicyError


@dataclass(frozen=True)
class ResolvedPolicy:
    entities: frozenset[str]
    thresholds: dict[str, float]
    default_threshold: float


def resolve_policy(
    tenant: Tenant,
    request_override: PolicyConfig | None,
    settings: Settings,
) -> ResolvedPolicy:
    base = tenant.policy
    entities = set(request_override.entities) if request_override else set(base.entities)
    thresholds = dict(base.thresholds)
    if request_override:
        thresholds.update(request_override.thresholds)

    unknown = entities - set(settings.default_entities)
    if unknown:
        raise InvalidPolicyError(f"Unknown entity types: {sorted(unknown)}")

    return ResolvedPolicy(
        entities=frozenset(entities),
        thresholds=thresholds,
        default_threshold=settings.default_threshold,
    )


def threshold_for(policy: ResolvedPolicy, entity_type: str) -> float:
    return policy.thresholds.get(entity_type, policy.default_threshold)
