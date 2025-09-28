import datetime as dt
from typing import Any, cast

import msgspec
import pytest

import mere.orm as orm_module
from mere.audit import AuditActor, AuditTrail, audit_context
from mere.database import Database, DatabaseConfig, PoolConfig
from mere.id57 import generate_id57
from mere.models import AppSecret, BillingRecord, BillingStatus, Passkey, TenantUser
from mere.orm import (
    ORM,
    Model,
    ModelInfo,
    ModelRegistry,
    ModelScope,
    _apply_insert_metadata,
    _apply_update_metadata,
    default_registry,
    model,
)
from mere.tenancy import TenantResolver
from tests.support import FakeConnection, FakePool


@pytest.mark.asyncio
async def test_admin_model_insert_and_select() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://"), admin_schema="admin")
    database = Database(config, pool=pool)
    orm = ORM(database)

    record = BillingRecord(
        id=generate_id57(),
        customer_id=generate_id57(),
        plan_code="enterprise",
        status=BillingStatus.ACTIVE,
        amount_due_cents=120000,
        currency="USD",
        cycle_start=dt.datetime.now(dt.timezone.utc),
        cycle_end=dt.datetime.now(dt.timezone.utc),
        created_at=dt.datetime.now(dt.timezone.utc),
        updated_at=dt.datetime.now(dt.timezone.utc),
        metadata={"region": "us"},
    )
    connection.queue_result([msgspec.to_builtins(record)])

    created = await orm.admin.billing.create(record)
    assert created == record
    insert_sql = connection.calls[-1][1]
    assert insert_sql.startswith('INSERT INTO "admin"."billing"')
    assert "RETURNING" in insert_sql
    assert '"id"' in insert_sql

    connection.queue_result([msgspec.to_builtins(record)])
    rows = await orm.select(
        BillingRecord,
        filters={"plan_code": "enterprise"},
        order_by=["plan_code desc", "created_at asc"],
        limit=1,
    )
    assert rows[0].plan_code == "enterprise"
    select_sql = connection.calls[-1][1]
    assert 'ORDER BY "plan_code" DESC, "created_at" ASC' in select_sql
    assert select_sql.endswith("LIMIT $2")
    assert connection.calls[-1][2] == ["enterprise", 1]

    connection.queue_result([msgspec.to_builtins(record)])
    plain_rows = await orm.select(BillingRecord, order_by=["plan_code"])
    assert plain_rows[0] == record
    assert 'ORDER BY "plan_code" ASC' in connection.calls[-1][1]


@pytest.mark.asyncio
async def test_tenant_model_operations() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://"), tenant_schema_template="tenant_{tenant}")
    database = Database(config, pool=pool)
    orm = ORM(database)

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    user = TenantUser(
        id=generate_id57(),
        email="user@example.com",
        hashed_password="hash",
        created_at=dt.datetime.now(dt.timezone.utc),
        updated_at=dt.datetime.now(dt.timezone.utc),
        is_active=True,
        last_sign_in_at=None,
    )
    updated_user = TenantUser(
        id=user.id,
        email=user.email,
        hashed_password=user.hashed_password,
        created_at=user.created_at,
        updated_at=dt.datetime.now(dt.timezone.utc),
        is_active=False,
        last_sign_in_at=None,
    )

    connection.queue_result([msgspec.to_builtins(user)])
    created = await orm.tenants.users.create(user, tenant=tenant)
    assert created.email == "user@example.com"

    manager = orm.manager(TenantUser)

    connection.queue_result([msgspec.to_builtins(user)])
    fetched = await manager.get(tenant=tenant, filters={"id": user.id})
    assert fetched == user

    connection.queue_result([msgspec.to_builtins(user)])
    listing = await manager.list(tenant=tenant, filters=None, order_by=["email asc"], limit=None)
    assert listing[0] == user

    connection.queue_result([msgspec.to_builtins(updated_user)])
    updated = await manager.update({"is_active": False}, tenant=tenant, filters={"id": user.id})
    assert updated[0] == updated_user

    connection.queue_result([msgspec.to_builtins(updated_user)])
    repeated = await manager.update({}, tenant=tenant, filters={"id": user.id})
    assert repeated[0] == updated_user

    connection.queue_result([])
    missing = await manager.get(tenant=tenant, filters={"id": generate_id57()})
    assert missing is None

    connection.queue_result([])
    deleted = await manager.delete(tenant=tenant, filters={"id": generate_id57()})
    assert deleted == 0

    first_manager = orm.tenants.users
    second_manager = orm.tenants.users
    assert first_manager is second_manager
    with pytest.raises(AttributeError):
        getattr(orm.admin, "__missing__")


def test_registry_accessor_and_namespace() -> None:
    registry = default_registry()
    billing_info = registry.get_by_accessor("admin", "billing")
    assert billing_info.table == "billing"
    users_info = registry.get_by_accessor("tenant", "users")
    assert users_info.model is TenantUser
    with pytest.raises(LookupError):
        registry.get_by_accessor("admin", "missing")

    orm = ORM(Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=FakePool()))
    admin_manager = orm.admin.billing
    assert orm.admin.billing is admin_manager
    with pytest.raises(LookupError):
        orm.admin.missing
    with pytest.raises(AttributeError):
        orm.admin.app_secrets
    with pytest.raises(AttributeError):
        orm.tenants.passkeys


@pytest.mark.asyncio
async def test_restricted_models_not_exposed() -> None:
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=FakePool())
    orm = ORM(database)
    with pytest.raises(AttributeError):
        orm.admin.app_secrets
    with pytest.raises(AttributeError):
        orm.tenants.passkeys
    with pytest.raises(PermissionError):
        await orm.select(AppSecret)
    with pytest.raises(PermissionError):
        await orm.insert(AppSecret, {"secret_value": "s", "salt": "t"})
    with pytest.raises(PermissionError):
        await orm.update(AppSecret, {"secret_value": "x"})
    with pytest.raises(PermissionError):
        await orm.delete(AppSecret)
    with pytest.raises(PermissionError):
        orm.manager(AppSecret)
    with pytest.raises(PermissionError):
        await orm.select(Passkey)
    with pytest.raises(PermissionError):
        orm.manager(Passkey)


@pytest.mark.asyncio
async def test_manager_with_mapping_payload() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://"), admin_schema="admin")
    database = Database(config, pool=pool)
    orm = ORM(database)

    record = BillingRecord(
        id=generate_id57(),
        customer_id=generate_id57(),
        plan_code="basic",
        status=BillingStatus.ACTIVE,
        amount_due_cents=1000,
        currency="USD",
        cycle_start=dt.datetime.now(dt.timezone.utc),
        cycle_end=dt.datetime.now(dt.timezone.utc),
        created_at=dt.datetime.now(dt.timezone.utc),
        updated_at=dt.datetime.now(dt.timezone.utc),
        metadata={},
    )
    connection.queue_result([msgspec.to_builtins(record)])
    created = await orm.insert(BillingRecord, msgspec.to_builtins(record))
    assert created.plan_code == "basic"

    updated_record = BillingRecord(
        id=record.id,
        customer_id=record.customer_id,
        plan_code=record.plan_code,
        status=record.status,
        amount_due_cents=2000,
        currency=record.currency,
        cycle_start=record.cycle_start,
        cycle_end=record.cycle_end,
        created_at=record.created_at,
        updated_at=dt.datetime.now(dt.timezone.utc),
        metadata=record.metadata,
    )
    connection.queue_result([msgspec.to_builtins(updated_record)])
    results = await orm.update(BillingRecord, {"amount_due_cents": 2000}, filters={"id": record.id})
    assert results[0] == updated_record

    updated_record_global = BillingRecord(
        id=record.id,
        customer_id=record.customer_id,
        plan_code=record.plan_code,
        status=record.status,
        amount_due_cents=3000,
        currency=record.currency,
        cycle_start=record.cycle_start,
        cycle_end=record.cycle_end,
        created_at=record.created_at,
        updated_at=dt.datetime.now(dt.timezone.utc),
        metadata=record.metadata,
    )
    connection.queue_result([msgspec.to_builtins(updated_record_global)])
    all_rows = await orm.update(BillingRecord, {"amount_due_cents": 3000})
    assert all_rows[0] == updated_record_global

    connection.queue_result([])
    count = await orm.delete(BillingRecord, filters={"id": generate_id57()})
    assert count == 0


def test_unknown_field_errors() -> None:
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=FakePool())
    orm = ORM(database)
    with pytest.raises(LookupError):
        orm._build_filters(default_registry().info_for(BillingRecord), {"unknown": 1})


@pytest.mark.asyncio
async def test_manager_update_unknown_field_raises() -> None:
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=FakePool())
    orm = ORM(database)
    manager = orm.manager(BillingRecord)
    with pytest.raises(LookupError):
        await manager.update({"missing": 1})


def test_registry_prevents_duplicates_and_normalizes_accessor() -> None:
    registry = ModelRegistry()

    @model(scope=ModelScope.ADMIN, table="demo_entries", registry=registry)
    class Demo(Model):
        id: int

    info = registry.info_for(Demo)
    with pytest.raises(ValueError):
        registry.register(info)

    @model(
        scope=ModelScope.ADMIN,
        table="demo_other",
        accessor="Orders-Manage!!",
        registry=registry,
    )
    class DemoAccessor(Model):
        id: int

    fetched = registry.get_by_accessor("admin", "orders_manage")
    assert fetched is registry.info_for(DemoAccessor)
    assert any(info.model in {Demo, DemoAccessor} for info in registry.models())

    with pytest.raises(ValueError):

        @model(scope=ModelScope.ADMIN, table="demo_entries", registry=registry)
        class Duplicate(Model):
            id: int


def test_normalize_accessor_fallback_behavior() -> None:
    assert orm_module._normalize_accessor("Orders-Manage!!") == "orders_manage"
    assert orm_module._normalize_accessor("!!!") == "!!!"


def test_model_redacted_field_validation() -> None:
    registry = ModelRegistry()

    with pytest.raises(ValueError):

        @model(scope=ModelScope.ADMIN, table="invalid", registry=registry, redacted_fields=("missing",))
        class InvalidModel(Model):
            id: str


@pytest.mark.asyncio
async def test_projection_with_column_alias_and_filterless_delete() -> None:
    registry = ModelRegistry()

    @model(scope=ModelScope.ADMIN, table="alias_demo", registry=registry)
    class AliasModel(Model):
        id: int
        display_name: str = msgspec.field(name="display_name_column")

    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://"), admin_schema="admin"), pool=pool)
    orm = ORM(database, registry=registry)

    item = AliasModel(id=1, display_name="Sample")
    connection.queue_result([msgspec.to_builtins(item)])
    results = await orm.select(AliasModel)
    assert results[0] == item
    select_sql = connection.calls[-1][1]
    assert '"display_name_column" AS "display_name"' in select_sql

    connection.queue_result([])
    deleted = await orm.delete(AliasModel)
    assert deleted == 0


class RecordingAuditTrail:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, str | None, dict[str, Any], dict[str, Any]]] = []

    async def record_model_change(
        self,
        *,
        info,
        action,
        tenant,
        data,
        changes,
        before=None,
    ) -> None:  # type: ignore[no-untyped-def]
        tenant_name = tenant.tenant if tenant else None
        action_value = getattr(action, "value", action)
        self.events.append(
            (
                action_value,
                info.table,
                tenant_name,
                dict(data),
                dict(changes),
            )
        )


@pytest.mark.asyncio
async def test_orm_emits_audit_events() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://"), tenant_schema_template="tenant_{tenant}")
    database = Database(config, pool=pool)
    audit = RecordingAuditTrail()
    orm = ORM(database, audit_trail=cast(AuditTrail, audit))

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    user = TenantUser(email="user@example.com", hashed_password="hash")
    connection.queue_result([msgspec.to_builtins(user)])
    actor = AuditActor(id="admin", type="AdminUser")
    async with audit_context(tenant=tenant, actor=actor):
        created = await orm.tenants.users.create(user, tenant=tenant)
        assert created.email == "user@example.com"

        updated_user = TenantUser(
            id=created.id,
            email=created.email,
            hashed_password=created.hashed_password,
            created_at=created.created_at,
            created_by=created.created_by,
            updated_at=dt.datetime.now(dt.timezone.utc),
            updated_by=actor.id,
            username=created.username,
            password_salt=created.password_salt,
            password_secret=created.password_secret,
            is_active=False,
            last_sign_in_at=created.last_sign_in_at,
            mfa_enforced=created.mfa_enforced,
            mfa_enrolled_at=created.mfa_enrolled_at,
            federated_subjects=list(created.federated_subjects),
        )
        connection.queue_result([msgspec.to_builtins(updated_user)])
        await orm.tenants.users.update({"is_active": False}, tenant=tenant, filters={"id": created.id})

        connection.queue_result([msgspec.to_builtins(updated_user)])
        await orm.tenants.users.delete(tenant=tenant, filters={"id": created.id})

    actions = [event[0] for event in audit.events]
    assert actions == ["insert", "update", "delete"]
    insert_event = audit.events[0]
    assert insert_event[1] == "users"
    assert insert_event[2] == "acme"
    assert insert_event[4]["created_by"] == actor.id
    update_event = audit.events[1]
    assert update_event[4]["updated_by"] == actor.id


@pytest.mark.asyncio
async def test_apply_insert_metadata_populates_audit_fields() -> None:
    info = default_registry().info_for(TenantUser)
    payload: dict[str, Any] = {
        "created_at": None,
        "updated_at": None,
        "created_by": None,
        "updated_by": None,
    }
    actor = AuditActor(id="admin", type="AdminUser")
    async with audit_context(tenant=None, actor=actor):
        _apply_insert_metadata(info, payload)
    assert isinstance(payload["created_at"], dt.datetime)
    assert payload["updated_at"] == payload["created_at"]
    assert payload["created_by"] == actor.id
    assert payload["updated_by"] == actor.id


@pytest.mark.asyncio
async def test_apply_update_metadata_uses_current_actor() -> None:
    info = default_registry().info_for(TenantUser)
    values: dict[str, Any] = {}
    actor = AuditActor(id="editor", type="AdminUser")
    async with audit_context(tenant=None, actor=actor):
        _apply_update_metadata(info, values)
    assert isinstance(values["updated_at"], dt.datetime)
    assert values["updated_by"] == actor.id


@pytest.mark.asyncio
async def test_apply_insert_metadata_preserves_existing_actor_fields() -> None:
    info = default_registry().info_for(TenantUser)
    payload: dict[str, Any] = {
        "created_at": None,
        "updated_at": None,
        "created_by": "system",
        "updated_by": "system",
    }
    actor = AuditActor(id="admin", type="AdminUser")
    async with audit_context(tenant=None, actor=actor):
        _apply_insert_metadata(info, payload)
    assert payload["created_by"] == "system"
    assert payload["updated_by"] == "system"


def test_apply_insert_metadata_without_actor_defaults() -> None:
    info = default_registry().info_for(TenantUser)
    payload: dict[str, Any] = {"created_at": None, "updated_at": None}
    _apply_insert_metadata(info, payload)
    assert "created_by" not in payload
    assert "updated_by" not in payload


def test_apply_update_metadata_without_actor() -> None:
    info = default_registry().info_for(TenantUser)
    values: dict[str, Any] = {}
    _apply_update_metadata(info, values)
    assert "updated_by" not in values


def test_apply_insert_metadata_skips_when_field_missing() -> None:
    info = ModelInfo(
        model=TenantUser,
        table="users",
        scope="tenant",
        schema=None,
        identity=("id",),
        fields=tuple(),
        accessor="users",
        field_map={},
        exposed=True,
        redacted_fields=frozenset(),
    )
    payload: dict[str, Any] = {"created_at": None, "updated_at": None}
    _apply_insert_metadata(info, payload)
    assert payload["created_at"] is None
    assert payload["updated_at"] is None


def test_apply_update_metadata_skips_when_field_missing() -> None:
    info = ModelInfo(
        model=TenantUser,
        table="users",
        scope="tenant",
        schema=None,
        identity=("id",),
        fields=tuple(),
        accessor="users",
        field_map={},
        exposed=True,
        redacted_fields=frozenset(),
    )
    values: dict[str, Any] = {}
    _apply_update_metadata(info, values)
    assert values == {}
