from __future__ import annotations

import datetime as dt

import msgspec
import pytest

from mere.audit import INSERT, UPDATE, AuditActor, AuditTrail, audit_context
from mere.database import Database, DatabaseConfig, PoolConfig
from mere.models import (
    AdminAuditLogEntry,
    BillingRecord,
    BillingStatus,
    TenantAuditLogEntry,
    TenantUser,
)
from mere.orm import default_registry
from mere.tenancy import TenantResolver
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
    before = {"email": "old@example.com", "hashed_password": "old"}
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


def test_audit_sanitize_model_payload_handles_non_mapping() -> None:
    trail, _ = _trail()
    info = default_registry().info_for(TenantUser)
    assert trail.sanitize_model_payload(info, ["invalid"]) == {}


def test_audit_metadata_without_model_info() -> None:
    trail, _ = _trail()
    metadata = trail._metadata_for(info=None, before={"token": "value"}, context=None)
    assert metadata["before"]["token"] == "value"
