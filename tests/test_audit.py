from __future__ import annotations

import datetime as dt

import msgspec
import pytest

from artemis.audit import DELETE, INSERT, UPDATE, AuditActor, AuditTrail, audit_context
from artemis.database import Database, DatabaseConfig, PoolConfig
from artemis.models import (
    AdminAuditLogEntry,
    AdminUser,
    BillingRecord,
    BillingStatus,
    SessionLevel,
    SessionToken,
    TenantAuditLogEntry,
    TenantUser,
)
from artemis.orm import default_registry
from artemis.tenancy import TenantResolver
from tests.support import FakeConnection, FakePool


@pytest.mark.asyncio
async def test_audit_trail_records_tenant_mutation() -> None:
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    actor = AuditActor(id="admin-1", type="AdminUser")
    user = TenantUser(email="user@example.com", hashed_password="secret")
    row = msgspec.to_builtins(user)

    async with audit_context(tenant=tenant, actor=actor):
        await trail.record_model_change(
            info=default_registry().info_for(TenantUser),
            action=INSERT,
            tenant=tenant,
            data=row,
            changes=row,
        )

    _, sql, params, _ = connection.calls[-1]
    assert sql.startswith("INSERT INTO")
    assert '"tenant_acme"."audit_log"' in sql
    info = default_registry().info_for(TenantAuditLogEntry)
    inserted = {field.name: value for field, value in zip(info.fields, params)}
    assert inserted["action"] == "insert"
    assert inserted["actor_id"] == actor.id
    assert inserted["created_by"] == actor.id
    assert inserted["metadata"]["tenant"] == "acme"
    assert inserted["changes"]["email"] == "user@example.com"
    assert "hashed_password" not in inserted["changes"]
    assert inserted["created_at"] == now
    assert inserted["updated_at"] == now


@pytest.mark.asyncio
async def test_audit_trail_records_admin_update_without_actor() -> None:
    now = dt.datetime(2024, 2, 1, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)

    record = BillingRecord(
        customer_id="cust-1",
        plan_code="enterprise",
        status=BillingStatus.ACTIVE,
        amount_due_cents=1000,
        currency="USD",
        cycle_start=now,
        cycle_end=now,
        metadata={},
    )
    row = msgspec.to_builtins(record)
    await trail.record_model_change(
        info=default_registry().info_for(BillingRecord),
        action=UPDATE,
        tenant=None,
        data=row,
        changes={"status": BillingStatus.PAST_DUE.value},
    )

    _, sql, params, _ = connection.calls[-1]
    assert '"admin"."admin_audit_log"' in sql
    info = default_registry().info_for(AdminAuditLogEntry)
    inserted = {field.name: value for field, value in zip(info.fields, params)}
    assert inserted["actor_id"] is None
    assert inserted["entity_id"] == record.id
    assert inserted["changes"]["status"] == BillingStatus.PAST_DUE.value
    assert "tenant" not in inserted["metadata"]


@pytest.mark.asyncio
async def test_audit_trail_records_custom_event() -> None:
    now = dt.datetime(2024, 3, 1, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")
    actor = AuditActor(id="system", type="ServiceAccount")
    async with audit_context(tenant=tenant, actor=actor):
        await trail.record_custom(
            scope="tenant",
            tenant=tenant,
            action="custom",
            entity_type="Webhook",
            entity_id="wh_123",
            changes={"event": "ping"},
            metadata={"source": "scheduler"},
        )

    _, sql, params, _ = connection.calls[-1]
    assert '"tenant_acme"."audit_log"' in sql
    info = default_registry().info_for(TenantAuditLogEntry)
    inserted = {field.name: value for field, value in zip(info.fields, params)}
    assert inserted["action"] == "custom"
    assert inserted["actor_type"] == "ServiceAccount"
    assert inserted["changes"]["event"] == "ping"
    assert inserted["metadata"]["source"] == "scheduler"


def _trail() -> tuple[AuditTrail, FakeConnection]:
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry())
    return trail, connection


def test_audit_trail_caches_entry_info() -> None:
    trail, _ = _trail()
    first = trail._entry_info_for_scope("tenant")
    second = trail._entry_info_for_scope("tenant")
    assert first is second


@pytest.mark.asyncio
async def test_audit_trail_write_entry_handles_missing_payload() -> None:
    trail, connection = _trail()
    admin_info = trail._entry_info_for_scope("admin")
    await trail._write_entry(admin_info, {}, None)
    assert connection.calls == []
    await trail._write_entry(admin_info, {"action": "noop"}, None)
    assert connection.calls[-1][1].startswith("INSERT INTO")


def test_audit_identity_returns_none_when_missing() -> None:
    trail, _ = _trail()
    user_info = default_registry().info_for(TenantUser)
    assert trail._identity_from_row(user_info, {"id": None}) is None


@pytest.mark.asyncio
async def test_audit_metadata_includes_before_snapshot() -> None:
    trail, connection = _trail()
    actor = AuditActor(id="admin", type="AdminUser")
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")
    user = TenantUser(email="user@example.com", hashed_password="secret")
    row = msgspec.to_builtins(user)
    before = {"email": "old@example.com", "hashed_password": "super-secret"}
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
    before_snapshot = inserted["metadata"]["before"]
    assert before_snapshot["email"] == "old@example.com"
    assert "hashed_password" not in before_snapshot


@pytest.mark.asyncio
async def test_audit_trail_redacts_session_token_payloads() -> None:
    now = dt.datetime(2024, 4, 1, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")
    info = default_registry().info_for(SessionToken)
    audit_info = default_registry().info_for(TenantAuditLogEntry)

    token = SessionToken(
        id="tok_123",
        user_id="user-123",
        token="secret-token",
        expires_at=now + dt.timedelta(hours=1),
        level=SessionLevel.PASSWORD_ONLY,
    )
    row = msgspec.to_builtins(token)

    async with audit_context(tenant=tenant, actor=None):
        await trail.record_model_change(
            info=info,
            action=INSERT,
            tenant=tenant,
            data=row,
            changes=row,
        )

    _, _, params, _ = connection.calls[-1]
    inserted = {field.name: value for field, value in zip(audit_info.fields, params)}
    assert inserted["changes"]["user_id"] == token.user_id
    assert "token" not in inserted["changes"]

    changes = {"token": "rotated-token", "revoked_at": now}
    before = {"token": "secret-token", "revoked_at": None}
    async with audit_context(tenant=tenant, actor=None):
        await trail.record_model_change(
            info=info,
            action=UPDATE,
            tenant=tenant,
            data=row,
            changes=changes,
            before=before,
        )

    _, _, params, _ = connection.calls[-1]
    inserted = {field.name: value for field, value in zip(audit_info.fields, params)}
    expected_timestamp = msgspec.to_builtins(now)
    assert inserted["changes"] == {"revoked_at": expected_timestamp}
    before_snapshot = inserted["metadata"]["before"]
    assert before_snapshot["revoked_at"] is None
    assert "token" not in before_snapshot

    delete_before = dict(row)
    async with audit_context(tenant=tenant, actor=None):
        await trail.record_model_change(
            info=info,
            action=DELETE,
            tenant=tenant,
            data=row,
            changes={"token": "should-disappear"},
            before=delete_before,
        )

    _, _, params, _ = connection.calls[-1]
    inserted = {field.name: value for field, value in zip(audit_info.fields, params)}
    assert inserted["changes"] == {}
    before_snapshot = inserted["metadata"]["before"]
    assert before_snapshot["user_id"] == token.user_id
    assert "token" not in before_snapshot


@pytest.mark.asyncio
async def test_audit_trail_redacts_admin_user_secrets() -> None:
    now = dt.datetime(2024, 5, 1, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)
    info = default_registry().info_for(AdminUser)
    audit_info = default_registry().info_for(AdminAuditLogEntry)

    admin = AdminUser(
        id="admin_123",
        email="admin@example.com",
        hashed_password="hashed-value",
        password_salt="salt",
        password_secret="secret",
        mfa_enforced=True,
        mfa_enrolled_at=now,
    )
    row = msgspec.to_builtins(admin)

    await trail.record_model_change(
        info=info,
        action=INSERT,
        tenant=None,
        data=row,
        changes=row,
    )

    _, _, params, _ = connection.calls[-1]
    inserted = {field.name: value for field, value in zip(audit_info.fields, params)}
    assert inserted["changes"]["email"] == "admin@example.com"
    for secret_field in (
        "hashed_password",
        "password_salt",
        "password_secret",
        "mfa_enforced",
        "mfa_enrolled_at",
    ):
        assert secret_field not in inserted["changes"]

    changes = {"hashed_password": "rotated", "last_sign_in_at": now}
    before = {"hashed_password": "hashed-value", "last_sign_in_at": None}
    await trail.record_model_change(
        info=info,
        action=UPDATE,
        tenant=None,
        data=row,
        changes=changes,
        before=before,
    )

    _, _, params, _ = connection.calls[-1]
    inserted = {field.name: value for field, value in zip(audit_info.fields, params)}
    expected_timestamp = msgspec.to_builtins(now)
    assert inserted["changes"] == {"last_sign_in_at": expected_timestamp}
    before_snapshot = inserted["metadata"]["before"]
    assert before_snapshot["last_sign_in_at"] is None
    assert "hashed_password" not in before_snapshot

    delete_before = {"email": "admin@example.com", "password_secret": "secret"}
    await trail.record_model_change(
        info=info,
        action=DELETE,
        tenant=None,
        data=row,
        changes={"password_secret": "should-disappear"},
        before=delete_before,
    )

    _, _, params, _ = connection.calls[-1]
    inserted = {field.name: value for field, value in zip(audit_info.fields, params)}
    assert inserted["changes"] == {}
    before_snapshot = inserted["metadata"]["before"]
    assert before_snapshot["email"] == "admin@example.com"
    assert "password_secret" not in before_snapshot
