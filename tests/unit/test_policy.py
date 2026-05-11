from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from pii_cleaner.config.settings import PolicyConfig, Settings, Tenant, TenantKey
from pii_cleaner.core.policy import resolve_policy, threshold_for
from pii_cleaner.errors import InvalidPolicyError

_DUMMY_HASH = PasswordHasher().hash("policy-test-key")


def _tenant() -> Tenant:
    return Tenant(
        id="acme",
        keys=[TenantKey(hash=_DUMMY_HASH)],
        policy=PolicyConfig(entities=["EMAIL_ADDRESS"], thresholds={"EMAIL_ADDRESS": 0.9}),
    )


def test_resolve_uses_tenant_policy_when_no_override() -> None:
    policy = resolve_policy(_tenant(), None, Settings())
    assert policy.entities == frozenset({"EMAIL_ADDRESS"})
    assert threshold_for(policy, "EMAIL_ADDRESS") == 0.9


def test_override_replaces_entities_and_merges_thresholds() -> None:
    override = PolicyConfig(entities=["PERSON"], thresholds={"PERSON": 0.6})
    policy = resolve_policy(_tenant(), override, Settings())
    assert policy.entities == frozenset({"PERSON"})
    assert threshold_for(policy, "PERSON") == 0.6
    # Thresholds from tenant default still present for other keys.
    assert threshold_for(policy, "EMAIL_ADDRESS") == 0.9


def test_unknown_entity_type_rejected() -> None:
    override = PolicyConfig(entities=["NOT_AN_ENTITY"])
    with pytest.raises(InvalidPolicyError):
        resolve_policy(_tenant(), override, Settings())


def test_default_threshold_when_unspecified() -> None:
    tenant = Tenant(
        id="x", keys=[TenantKey(hash=_DUMMY_HASH)], policy=PolicyConfig(entities=["PERSON"])
    )
    policy = resolve_policy(tenant, None, Settings())
    assert threshold_for(policy, "PERSON") == Settings().default_threshold
