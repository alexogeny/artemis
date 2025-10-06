"""HIPAA Security Rule regression tests for the Mere authentication and auditing stack."""

from __future__ import annotations

import datetime as dt

import msgspec
import pytest

from mere.audit import UPDATE, AuditActor, AuditTrail, audit_context
from mere.authentication import AuthenticationError, AuthenticationRateLimiter
from mere.database import Database, DatabaseConfig, PoolConfig
from mere.models import TenantAuditLogEntry, TenantUser
from mere.orm import default_registry
from mere.tenancy import TenantResolver
from tests.support import FakeConnection, FakePool


@pytest.mark.asyncio
async def test_hipaa_rate_limiter_enforces_account_lockouts() -> None:
    """164.308(a)(5)(ii)(C) requires automatic lockouts after repeated failures."""

    rate_limiter = AuthenticationRateLimiter(max_attempts=2, lockout_period=dt.timedelta(minutes=15))
    now = dt.datetime(2024, 5, 1, tzinfo=dt.timezone.utc)

    await rate_limiter.enforce(["tenant:acme:user"], now)
    await rate_limiter.record_failure(["tenant:acme:user"], now)
    await rate_limiter.record_failure(["tenant:acme:user"], now + dt.timedelta(seconds=1))

    with pytest.raises(AuthenticationError) as excinfo:
        await rate_limiter.enforce(["tenant:acme:user"], now + dt.timedelta(seconds=2))
    assert str(excinfo.value) == "account_locked"


@pytest.mark.asyncio
async def test_hipaa_rate_limiter_resets_after_lockout_window() -> None:
    """164.308(a)(5) requires lockouts to expire after the defined interval."""

    rate_limiter = AuthenticationRateLimiter(max_attempts=2, lockout_period=dt.timedelta(seconds=2))
    now = dt.datetime(2024, 5, 1, 12, 0, tzinfo=dt.timezone.utc)
    key = ["tenant:acme:clinician"]

    await rate_limiter.record_failure(key, now)
    await rate_limiter.record_failure(key, now + dt.timedelta(milliseconds=500))

    with pytest.raises(AuthenticationError):
        await rate_limiter.enforce(key, now + dt.timedelta(seconds=1))

    # After the lockout window has passed the clinician may attempt to sign in again.
    await rate_limiter.enforce(key, now + dt.timedelta(seconds=3))


@pytest.mark.asyncio
async def test_hipaa_rate_limiter_applies_progressive_cooldown() -> None:
    """164.308(a)(5)(ii)(B) mandates throttling before full lockout."""

    rate_limiter = AuthenticationRateLimiter(
        max_attempts=3,
        base_cooldown=dt.timedelta(seconds=4),
        max_cooldown=dt.timedelta(seconds=8),
    )
    now = dt.datetime(2024, 5, 1, 13, 0, tzinfo=dt.timezone.utc)
    key = ["tenant:beta:clinician"]

    await rate_limiter.enforce(key, now)
    await rate_limiter.record_failure(key, now)

    with pytest.raises(AuthenticationError) as excinfo:
        await rate_limiter.enforce(key, now + dt.timedelta(seconds=2))
    assert str(excinfo.value) == "rate_limited"


@pytest.mark.asyncio
async def test_hipaa_rate_limiter_prunes_historic_identities() -> None:
    """164.310(d)(2)(ii) expects stale authentication identifiers to be purged."""

    rate_limiter = AuthenticationRateLimiter(max_attempts=1, max_entries=1)
    now = dt.datetime(2024, 5, 1, 14, 0, tzinfo=dt.timezone.utc)

    await rate_limiter.record_failure(["tenant:acme:patient"], now)
    await rate_limiter.record_failure(["tenant:beta:patient"], now + dt.timedelta(seconds=1))

    # The acme identity should have been pruned when the beta patient was recorded.
    await rate_limiter.enforce(["tenant:acme:patient"], now + dt.timedelta(seconds=2))


@pytest.mark.asyncio
async def test_hipaa_rate_limiter_clears_state_after_success() -> None:
    """164.308(a)(5)(ii)(B) resets throttling once a user successfully authenticates."""

    rate_limiter = AuthenticationRateLimiter(max_attempts=1, lockout_period=dt.timedelta(minutes=5))
    now = dt.datetime(2024, 5, 1, 15, 0, tzinfo=dt.timezone.utc)
    key = ["tenant:acme:nurse"]

    await rate_limiter.record_failure(key, now)
    with pytest.raises(AuthenticationError):
        await rate_limiter.enforce(key, now + dt.timedelta(seconds=1))

    await rate_limiter.record_success(key)
    await rate_limiter.enforce(key, now + dt.timedelta(seconds=2))


@pytest.mark.asyncio
async def test_hipaa_audit_metadata_redacts_protected_health_information() -> None:
    """164.312(b) audit controls demand redaction of PHI snapshots."""

    now = dt.datetime(2024, 5, 2, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    actor = AuditActor(id="clinician-1", type="Clinician")
    before = {"email": "old@example.com", "hashed_password": "legacy"}
    user = TenantUser(email="patient@example.com", hashed_password="secret")
    row = msgspec.to_builtins(user)

    async with audit_context(tenant=tenant, actor=actor):
        await trail.record_model_change(
            info=default_registry().info_for(TenantUser),
            action=UPDATE,
            tenant=tenant,
            data=row,
            changes=row,
            before=before,
        )

    _, _, params, _ = connection.calls[-1]
    info = default_registry().info_for(TenantAuditLogEntry)
    inserted = {field.name: value for field, value in zip(info.fields, params)}
    assert inserted["metadata"]["before"]["email"] == "old@example.com"
    assert "hashed_password" not in inserted["metadata"]["before"]


@pytest.mark.asyncio
async def test_hipaa_rate_limiter_drops_inactive_entries() -> None:
    """164.308(a)(1)(ii)(D) prunes dormant login records after monitoring review."""

    rate_limiter = AuthenticationRateLimiter(window=dt.timedelta(seconds=1))
    now = dt.datetime(2024, 5, 1, 16, 0, tzinfo=dt.timezone.utc)
    key = ["tenant:beta:physician"]

    await rate_limiter.record_failure(key, now)
    await rate_limiter.enforce(key, now + dt.timedelta(seconds=2))


@pytest.mark.asyncio
async def test_hipaa_audit_custom_events_include_tenant_context() -> None:
    """164.312(b) requires tenant identifiers to accompany manual disclosures."""

    now = dt.datetime(2024, 5, 3, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    tenant = resolver.context_for("beta")
    actor = AuditActor(id="hipaa-officer", type="AdminUser")

    async with audit_context(tenant=tenant, actor=actor):
        await trail.record_custom(
            scope="tenant",
            tenant=tenant,
            action="export-phi",
            entity_type="patient_record",
            entity_id="record-123",  # unique disclosure identifier
            changes={"fields": ["dob", "lab_results"]},
        )

    insert_calls = [call for call in connection.calls if call[0] == "execute" and call[1].startswith("INSERT")]
    info = default_registry().info_for(TenantAuditLogEntry)
    row = {field.name: value for field, value in zip(info.fields, insert_calls[0][2])}
    assert row["entity_id"] == "record-123"
    assert row["metadata"]["tenant"] == "beta"
    assert row["changes"]["fields"] == ["dob", "lab_results"]


@pytest.mark.asyncio
async def test_hipaa_rate_limiter_isolates_user_identities() -> None:
    """164.312(a)(2)(i) enforces unique user identification in throttle states."""

    rate_limiter = AuthenticationRateLimiter(max_attempts=1, lockout_period=dt.timedelta(minutes=10))
    now = dt.datetime(2024, 5, 4, 9, tzinfo=dt.timezone.utc)
    acme_key = ["tenant:acme:oncologist"]
    beta_key = ["tenant:beta:oncologist"]

    await rate_limiter.record_failure(acme_key, now)

    # The beta oncologist should remain unaffected by the acme lockout state.
    await rate_limiter.enforce(beta_key, now + dt.timedelta(seconds=1))

    with pytest.raises(AuthenticationError) as excinfo:
        await rate_limiter.enforce(acme_key, now + dt.timedelta(seconds=1))
    assert str(excinfo.value) == "account_locked"


@pytest.mark.asyncio
async def test_hipaa_rate_limiter_caps_cooldown_to_policy_maximum() -> None:
    """164.308(a)(5)(ii)(D) requires defined maximum cooldown intervals for retries."""

    rate_limiter = AuthenticationRateLimiter(
        max_attempts=5,
        base_cooldown=dt.timedelta(seconds=4),
        max_cooldown=dt.timedelta(seconds=8),
    )
    now = dt.datetime(2024, 5, 4, 10, tzinfo=dt.timezone.utc)
    key = ["tenant:acme:researcher"]

    for offset in range(4):
        await rate_limiter.record_failure(key, now + dt.timedelta(seconds=offset))

    with pytest.raises(AuthenticationError) as excinfo:
        await rate_limiter.enforce(key, now + dt.timedelta(seconds=6))
    assert str(excinfo.value) == "rate_limited"

    # Once the capped eight second cooldown has elapsed the retry is authorised.
    await rate_limiter.enforce(key, now + dt.timedelta(seconds=12))
