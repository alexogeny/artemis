from __future__ import annotations

import datetime as dt
import sys
import types
import uuid
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, cast

import msgspec
import pytest

from mere import (  # type: ignore[attr-defined]
    Migration,
    MigrationContext,
    MigrationError,
    MigrationRunner,
    MigrationScope,
    Model,
    ModelScope,
    TenantContext,
    TenantResolver,
    create_table_for_model,
    generate_schema_migrations,
    model,
    run_sql,
)
from mere.cli import _load_environment, _models_by_scope, _render_migration_template
from mere.cli import main as cli_main
from mere.database import Database, DatabaseConfig, PoolConfig
from mere.migrations import (
    _resolve_model_schema,
    build_create_table_statement,
    identity_order_clause,
    projection,
    render_insert,
    render_literal,
    sql_type_for,
)
from mere.orm import FieldInfo, ModelInfo
from tests.support import FakeConnection, FakePool


@model(scope=ModelScope.ADMIN, table="test_admin")
class _TestAdminModel(Model):
    id: str
    name: str


@model(scope=ModelScope.TENANT, table="test_tenant")
class _TestTenantModel(Model):
    id: str
    tenant_value: str


class _ComplexStatus(Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class _RenderStatus(Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


def _database_with_connection(connection: FakeConnection) -> Database:
    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://demo"))
    return Database(config, pool=FakePool(connection))


def test_generate_schema_migrations_discovers_declared_models(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        Model,
        "declared_models",
        classmethod(lambda cls: (_TestAdminModel, _TestTenantModel)),
    )

    migrations = generate_schema_migrations(name_prefix="demo")
    names = {migration.name for migration in migrations}
    assert names == {"demo_admin", "demo_tenant"}
    for migration in migrations:
        assert migration.operations  # ensure operations populated


@pytest.mark.asyncio
async def test_migration_runner_executes_admin_and_tenant_scopes(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection()
    connection.queue_result([])  # _load_applied returns nothing
    database = _database_with_connection(connection)

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    tenants = [resolver.context_for("acme"), resolver.context_for("beta")]

    admin_migration = Migration(
        name="admin_setup",
        scope=MigrationScope.ADMIN,
        operations=(run_sql("SELECT 'admin'"),),
    )
    tenant_migration = Migration(
        name="tenant_setup",
        scope=MigrationScope.TENANT,
        operations=(run_sql("SELECT 'tenant'"),),
    )
    runner = MigrationRunner(
        database,
        migrations=[admin_migration, tenant_migration],
        tenant_provider=lambda: tenants,
    )

    applied = await runner.run_all()
    assert applied == ["admin_setup", "tenant_setup:acme", "tenant_setup:beta"]

    statements = [sql for method, sql, *_ in connection.calls if method == "execute"]
    assert "SELECT 'admin'" in statements
    assert statements.count("SELECT 'tenant'") == 2
    assert any("INSERT INTO" in sql for sql in statements)


@pytest.mark.asyncio
async def test_migration_runner_background(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)

    async def record(context) -> None:  # type: ignore[no-untyped-def]
        events.append(context.schema)

    migration = Migration(
        name="background_job",
        scope=MigrationScope.ADMIN,
        operations=(record,),
        background=True,
    )
    runner = MigrationRunner(database, migrations=[migration])

    task = await runner.run_in_background(scope=MigrationScope.ADMIN, background=True)
    result = await task
    assert result == ["background_job"]
    assert events == [database.config.admin_schema]


@pytest.mark.asyncio
async def test_create_table_operation_emits_expected_sql(monkeypatch: pytest.MonkeyPatch) -> None:
    @model(scope=ModelScope.ADMIN, table="complex_table")
    class ComplexModel(Model):  # type: ignore[misc, valid-type]
        id: str
        created_at: dt.datetime
        amount: int
        flag: bool = False
        tags: list[str] = msgspec.field(default_factory=list)
        payload: dict[str, Any] | None = None
        status: _ComplexStatus = _ComplexStatus.ACTIVE
        blob: bytes = b""

    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: (ComplexModel,)))
    connection = FakeConnection()
    database = _database_with_connection(connection)
    operation = create_table_for_model(ComplexModel)

    async with database.connection(schema=database.config.admin_schema) as conn:
        context = MigrationContext(
            database=database,
            connection=conn,
            tenant=None,
            schema=database.config.admin_schema,
        )
        await operation(context)

    statements = [sql for method, sql, *_ in connection.calls if method == "execute"]
    create_statement = next(sql for sql in statements if sql.startswith("CREATE TABLE"))
    assert '"flag" BOOLEAN' in create_statement and "DEFAULT FALSE" in create_statement
    assert '"tags" JSONB' in create_statement
    assert '"payload" JSONB' in create_statement
    assert '"status" TEXT' in create_statement
    assert '"blob" BYTEA' in create_statement


def test_migration_runs_for() -> None:
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    acme = resolver.context_for("acme")
    beta = resolver.context_for("beta")

    admin_migration = Migration(name="admin", scope=MigrationScope.ADMIN, operations=(run_sql("SELECT 1"),))
    assert admin_migration.runs_for(None)
    assert not admin_migration.runs_for(acme)

    tenant_migration = Migration(name="tenant", scope=MigrationScope.TENANT, operations=(run_sql("SELECT 1"),))
    assert tenant_migration.runs_for(acme)
    assert not tenant_migration.runs_for(None)

    targeted = Migration(
        name="targeted",
        scope=MigrationScope.TENANT,
        operations=(run_sql("SELECT 1"),),
        target_tenants=("beta",),
    )
    assert targeted.runs_for(beta)
    assert not targeted.runs_for(acme)


def test_render_insert_formats_values(monkeypatch: pytest.MonkeyPatch) -> None:
    @model(scope=ModelScope.ADMIN, table="render_table")
    class RenderModel(Model):  # type: ignore[misc, valid-type]
        id: str
        created_at: dt.datetime
        amount: int
        flag: bool
        tags: list[str]
        metadata: dict[str, Any]
        status: _RenderStatus
        blob: bytes

    info = getattr(RenderModel, "__model_info__")
    row = {
        "id": "abc",
        "created_at": dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
        "amount": 7,
        "flag": True,
        "tags": ["x", "y"],
        "metadata": {"k": "v"},
        "status": _RenderStatus.DISABLED,
        "blob": b"data",
    }
    statement = render_insert("admin", info, row)
    assert "'\\x64617461'::bytea" in statement
    assert "'TRUE'" in statement or "TRUE" in statement
    assert '"status"' in statement and "disabled" in statement
    assert '"metadata"' in statement


@pytest.mark.asyncio
async def test_migration_context_fetch_all() -> None:
    connection = FakeConnection()
    connection.queue_result([{"value": 1}])
    database = _database_with_connection(connection)
    async with database.connection(schema=database.config.admin_schema) as conn:
        context = MigrationContext(
            database=database,
            connection=conn,
            tenant=None,
            schema=database.config.admin_schema,
        )
        rows = await context.fetch_all("SELECT 1")
    assert rows[0]["value"] == 1


@pytest.mark.asyncio
async def test_migration_schema_placeholder_requires_tenant() -> None:
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    migration = Migration(
        name="bad_schema",
        scope=MigrationScope.ADMIN,
        operations=(run_sql("SELECT 1"),),
        schema="{tenant}_archive",
    )
    runner = MigrationRunner(database, migrations=[migration])
    with pytest.raises(MigrationError):
        await runner.run_all()


@pytest.mark.asyncio
async def test_snapshot_test_data_writes_sql(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    @model(scope=ModelScope.ADMIN, table="snapshot_demo_runner")
    class SnapshotModel(Model):  # type: ignore[misc, valid-type]
        id: str
        value: str

    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: (SnapshotModel,)))

    connection = FakeConnection()
    connection.queue_result([{"id": "abc", "value": "demo"}])
    database = _database_with_connection(connection)
    runner = MigrationRunner(database, migrations=[])

    destination = tmp_path / "snapshot.sql"
    await runner.snapshot_test_data(destination, tenants=[], include_admin=True)
    content = destination.read_text(encoding="utf-8")
    assert 'INSERT INTO "admin"."snapshot_demo_runner"' in content
    assert "'demo'" in content


@pytest.mark.asyncio
async def test_run_all_background_filters() -> None:
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    foreground = Migration(
        name="foreground",
        scope=MigrationScope.ADMIN,
        operations=(run_sql("SELECT 'fg'"),),
    )
    background = Migration(
        name="background",
        scope=MigrationScope.ADMIN,
        operations=(run_sql("SELECT 'bg'"),),
        background=True,
    )
    runner = MigrationRunner(database, migrations=[foreground, background])

    applied_foreground = await runner.run_all(background=False)
    assert applied_foreground == ["foreground"]

    connection.queue_result([{"migration_name": "foreground", "tenant": None}])
    applied_background = await runner.run_all(background=True)
    assert applied_background == ["background"]


@pytest.mark.asyncio
async def test_snapshot_skip_admin_includes_tenant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_connection = FakeConnection()
    tenant_connection.queue_result([{"id": "abc", "value": "demo"}])
    database = _database_with_connection(tenant_connection)
    runner = MigrationRunner(database, migrations=[])

    @model(scope=ModelScope.TENANT, table="tenant_snapshot")
    class TenantModel(Model):  # type: ignore[misc, valid-type]
        id: str
        value: str

    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: (TenantModel,)))

    tenant_resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = tenant_resolver.context_for("acme")
    destination = tmp_path / "tenant.sql"
    await runner.snapshot_test_data(destination, tenants=[tenant], include_admin=False)
    content = destination.read_text(encoding="utf-8")
    assert "-- tenant: acme" in content
    assert "tenant_snapshot" in content


def test_cli_migrate_uses_environment_module(monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "tests.cli_env"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)

    events: list[str] = []

    async def record(context) -> None:  # type: ignore[no-untyped-def]
        events.append(context.schema)

    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: (_TestAdminModel,)))
    module.get_database = lambda: database  # type: ignore[attr-defined]
    module.TENANTS = []  # type: ignore[attr-defined]
    module.MIGRATIONS = [  # type: ignore[attr-defined]
        Migration(name="cli_admin", scope=MigrationScope.ADMIN, operations=(record,)),
    ]
    sys.modules[module_name] = module
    try:
        assert cli_main(["migrate", "--module", module_name]) == 0
    finally:
        sys.modules.pop(module_name, None)
    assert events == [database.config.admin_schema]


def test_cli_migrate_background_filters(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    module_name = "tests.cli_background_env"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    events: list[tuple[str, str | None]] = []

    async def foreground(context) -> None:  # type: ignore[no-untyped-def]
        events.append(("fg", context.tenant.tenant if context.tenant else None))

    async def background(context) -> None:  # type: ignore[no-untyped-def]
        events.append(("bg", context.tenant.tenant if context.tenant else None))

    module.DATABASE = database  # type: ignore[attr-defined]
    module.get_tenants = lambda: [tenant]  # type: ignore[attr-defined]
    module.get_migrations = lambda: [  # type: ignore[attr-defined]
        Migration(name="fg_admin", scope=MigrationScope.ADMIN, operations=(foreground,)),
        Migration(name="bg_tenant", scope=MigrationScope.TENANT, operations=(background,), background=True),
    ]
    module.INCLUDE_MODEL_MIGRATIONS = False  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        assert cli_main(["migrate", "--module", module_name, "--skip-background"]) == 0
        out1 = capsys.readouterr()
        assert "applied fg_admin" in out1.out
        connection.queue_result([{"migration_name": "fg_admin", "tenant": None}])
        assert (
            cli_main(
                [
                    "migrate",
                    "--module",
                    module_name,
                    "--scope",
                    "tenant",
                    "--tenant",
                    "acme",
                    "--only-background",
                ]
            )
            == 0
        )
        out2 = capsys.readouterr()
        assert "applied bg_tenant:acme" in out2.out
    finally:
        sys.modules.pop(module_name, None)
    assert events == [("fg", None), ("bg", "acme")]


def test_cli_migrate_conflicting_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "tests.cli_conflict_env"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    module.get_database = lambda: database  # type: ignore[attr-defined]
    module.TENANTS = []  # type: ignore[attr-defined]
    module.MIGRATIONS = []  # type: ignore[attr-defined]
    module.INCLUDE_MODEL_MIGRATIONS = False  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        with pytest.raises(SystemExit):
            cli_main(
                [
                    "migrate",
                    "--module",
                    module_name,
                    "--only-background",
                    "--skip-background",
                ]
            )
    finally:
        sys.modules.pop(module_name, None)


def test_cli_migrate_prints_no_work(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    module_name = "tests.cli_empty_env"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    module.get_database = lambda: database  # type: ignore[attr-defined]
    module.TENANTS = []  # type: ignore[attr-defined]
    module.MIGRATIONS = []  # type: ignore[attr-defined]
    module.INCLUDE_MODEL_MIGRATIONS = False  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        assert cli_main(["migrate", "--module", module_name]) == 0
        output = capsys.readouterr()
        assert "No migrations executed" in output.out
    finally:
        sys.modules.pop(module_name, None)


def test_cli_make_migration_generates_template(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        Model,
        "declared_models",
        classmethod(lambda cls: (_TestAdminModel, _TestTenantModel)),
    )
    output_dir = tmp_path / "migrations"
    result = cli_main(
        [
            "make-migration",
            "Initial Schema",
            "--directory",
            str(output_dir),
            "--import",
            "tests.test_migrations",
        ]
    )
    assert result == 0
    path = output_dir / "initial_schema.py"
    content = path.read_text(encoding="utf-8")
    assert "create_table_for_model(_TestAdminModel)" in content
    assert "create_table_for_model(_TestTenantModel)" in content


def test_cli_snapshot_writes_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "tests.snapshot_env"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([{"id": "abc", "value": "demo"}])
    database = _database_with_connection(connection)

    @model(scope=ModelScope.ADMIN, table="snapshot_demo_cli")
    class SnapshotModel(Model):  # type: ignore[misc, valid-type]
        id: str
        value: str

    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: (SnapshotModel,)))

    module.get_database = lambda: database  # type: ignore[attr-defined]
    module.TENANTS = []  # type: ignore[attr-defined]
    module.MIGRATIONS = []  # type: ignore[attr-defined]
    module.INCLUDE_MODEL_MIGRATIONS = False  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        destination = tmp_path / "data.sql"
        assert (
            cli_main(
                [
                    "snapshot-test-data",
                    "--module",
                    module_name,
                    "--output",
                    str(destination),
                ]
            )
            == 0
        )
    finally:
        sys.modules.pop(module_name, None)
    content = destination.read_text(encoding="utf-8")
    assert 'INSERT INTO "admin"."snapshot_demo_cli"' in content


def test_cli_snapshot_skip_admin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "tests.snapshot_skip_env"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: ()))
    module.get_database = lambda: database  # type: ignore[attr-defined]
    module.TENANTS = []  # type: ignore[attr-defined]
    module.MIGRATIONS = []  # type: ignore[attr-defined]
    module.INCLUDE_MODEL_MIGRATIONS = False  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        destination = tmp_path / "skip.sql"
        assert (
            cli_main(
                [
                    "snapshot-test-data",
                    "--module",
                    module_name,
                    "--output",
                    str(destination),
                    "--skip-admin",
                ]
            )
            == 0
        )
    finally:
        sys.modules.pop(module_name, None)
    assert destination.exists()


@pytest.mark.asyncio
async def test_migration_apply_accepts_sync_operations() -> None:
    events: list[str] = []

    def record(context: MigrationContext) -> None:
        events.append(context.schema)

    migration = Migration(
        name="sync_only",
        scope=MigrationScope.ADMIN,
        operations=(record,),
    )
    connection = FakeConnection()
    database = _database_with_connection(connection)
    async with database.connection(schema=database.config.admin_schema) as conn:
        context = MigrationContext(
            database=database,
            connection=conn,
            tenant=None,
            schema=database.config.admin_schema,
        )
        await migration.apply(context)
    assert events == [database.config.admin_schema]


def test_migration_runner_duplicate_registration_rejected() -> None:
    database = _database_with_connection(FakeConnection())
    migration = Migration(
        name="dup",
        scope=MigrationScope.ADMIN,
        operations=(run_sql("SELECT 1"),),
    )
    runner = MigrationRunner(database)
    runner.add_migration(migration)
    with pytest.raises(MigrationError):
        runner.add_migration(migration)


def test_migration_runner_migrations_accessor() -> None:
    database = _database_with_connection(FakeConnection())
    migration = Migration(
        name="listed",
        scope=MigrationScope.ADMIN,
        operations=(run_sql("SELECT 1"),),
    )
    runner = MigrationRunner(database, migrations=[migration])
    assert runner.migrations() == (migration,)


@pytest.mark.asyncio
async def test_migration_runner_skips_previously_applied() -> None:
    connection = FakeConnection()
    connection.queue_result([])
    connection.queue_result([{"migration_name": "skip", "tenant": None}])
    database = _database_with_connection(connection)
    migration = Migration(
        name="skip",
        scope=MigrationScope.ADMIN,
        operations=(run_sql("SELECT 'skipped'"),),
    )
    runner = MigrationRunner(database, migrations=[migration])
    applied = await runner.run_all()
    assert applied == []
    executed = [sql for method, sql, *_ in connection.calls if method == "execute" and "skipped" in sql]
    assert not executed


@pytest.mark.asyncio
async def test_snapshot_test_data_no_statements(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: ()))
    database = _database_with_connection(FakeConnection())
    runner = MigrationRunner(database, migrations=[])
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")
    destination = tmp_path / "empty.sql"
    path = await runner.snapshot_test_data(destination, tenants=[tenant], include_admin=True)
    assert path.read_text(encoding="utf-8") == "-- no data\n"


@pytest.mark.asyncio
async def test_snapshot_scope_without_order_clause(monkeypatch: pytest.MonkeyPatch) -> None:
    @model(scope=ModelScope.ADMIN, table="snapshot_no_order", identity=())
    class SnapshotNoOrder(Model):  # type: ignore[misc, valid-type]
        id: str

    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: (SnapshotNoOrder,)))
    connection = FakeConnection()
    connection.queue_result([{"id": "abc"}])
    database = _database_with_connection(connection)
    runner = MigrationRunner(database, migrations=[])
    monkeypatch.setattr("mere.migrations.identity_order_clause", lambda info: "")
    rows = await runner._snapshot_scope(MigrationScope.ADMIN, None)
    select = next(sql for method, sql, *_ in connection.calls if sql.startswith("SELECT"))
    assert "ORDER BY" not in select
    assert rows[0].startswith("INSERT INTO")


@pytest.mark.asyncio
async def test_targets_for_migration_limits_tenants() -> None:
    connection = FakeConnection()
    database = _database_with_connection(connection)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    acme = resolver.context_for("acme")
    beta = resolver.context_for("beta")
    runner = MigrationRunner(database, tenant_provider=lambda: [acme, beta])
    migration = Migration(
        name="tenant_only",
        scope=MigrationScope.TENANT,
        operations=(run_sql("SELECT 1"),),
        target_tenants=("beta",),
    )
    selected = await runner._targets_for_migration(migration, None)
    assert all(tenant is not None for tenant in selected)
    assert [tenant.tenant for tenant in cast(list[TenantContext], selected)] == ["beta"]


@pytest.mark.asyncio
async def test_resolve_tenants_supports_async_provider() -> None:
    database = _database_with_connection(FakeConnection())
    runner = MigrationRunner(database)
    assert await runner._resolve_tenants() == ()
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    async def provider() -> list[TenantContext]:
        return [tenant]

    async_runner = MigrationRunner(database, tenant_provider=provider)
    assert await async_runner._resolve_tenants() == [tenant]


def test_schema_for_scope_variants() -> None:
    database = _database_with_connection(FakeConnection())
    runner = MigrationRunner(database)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    assert runner._schema_for_scope(MigrationScope.ADMIN, None, "custom_schema") == "custom_schema"
    assert runner._schema_for_scope(MigrationScope.ADMIN, None, None) == database.config.admin_schema
    assert runner._schema_for_scope(MigrationScope.TENANT, tenant, "{tenant}_data") == "acme_data"
    with pytest.raises(MigrationError):
        runner._schema_for_scope(MigrationScope.TENANT, None, None)
    with pytest.raises(MigrationError):
        runner._schema_for_scope(MigrationScope.ADMIN, None, "{tenant}_broken")


def test_resolve_model_schema_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    @model(scope=ModelScope.ADMIN, table="schema_override_admin", schema="shared_admin")
    class OverrideAdmin(Model):  # type: ignore[misc, valid-type]
        id: str

    @model(scope=ModelScope.TENANT, table="schema_override_tenant", schema="{tenant}_override")
    class OverrideTenant(Model):  # type: ignore[misc, valid-type]
        id: str

    admin_info = getattr(OverrideAdmin, "__model_info__")
    tenant_info = getattr(OverrideTenant, "__model_info__")
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    assert _resolve_model_schema(admin_info, "admin", None) == "shared_admin"
    assert _resolve_model_schema(tenant_info, "tenant", tenant) == "acme_override"
    with pytest.raises(MigrationError):
        _resolve_model_schema(tenant_info, "tenant", None)


def test_create_table_for_model_requires_metadata() -> None:
    class PlainModel(Model):
        id: str

    with pytest.raises(MigrationError):
        create_table_for_model(PlainModel)


def test_build_create_table_statement_identity_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    @model(scope=ModelScope.ADMIN, table="no_identity", identity=())
    class NoIdentity(Model):  # type: ignore[misc, valid-type]
        id: str
        name: str

    @model(scope=ModelScope.ADMIN, table="missing_identity", identity=("missing",))
    class MissingIdentity(Model):  # type: ignore[misc, valid-type]
        id: str
        name: str

    info_no_identity = getattr(NoIdentity, "__model_info__")
    info_missing = getattr(MissingIdentity, "__model_info__")
    statement_no_identity = build_create_table_statement("admin", info_no_identity, None)
    statement_missing = build_create_table_statement("admin", info_missing, None)
    assert "PRIMARY KEY" not in statement_no_identity
    assert "PRIMARY KEY" not in statement_missing


def test_sql_type_for_additional_types() -> None:
    class ExampleEnum(Enum):
        A = "a"

    assert sql_type_for(dt.datetime) == "TIMESTAMPTZ"
    assert sql_type_for(dt.date) == "DATE"
    assert sql_type_for(dt.time) == "TIME"
    assert sql_type_for(uuid.UUID) == "UUID"
    assert sql_type_for(ExampleEnum) == "TEXT"
    assert sql_type_for(float) == "DOUBLE PRECISION"
    assert sql_type_for(list[str]) == "JSONB"
    assert sql_type_for(dict[str, int]) == "JSONB"
    assert sql_type_for(Annotated[int, "id"]) == "BIGINT"
    assert sql_type_for(str | int) == "JSONB"


def test_projection_and_identity_order_clause_variants() -> None:
    alias_field = FieldInfo(
        name="py_name",
        column="db_name",
        python_type=str,
        has_default=False,
        default=msgspec.UNSET,
        default_factory=None,
    )
    other_field = FieldInfo(
        name="other",
        column="other",
        python_type=int,
        has_default=False,
        default=msgspec.UNSET,
        default_factory=None,
    )
    info = ModelInfo(
        model=_TestAdminModel,
        table="projection_table",
        scope="admin",
        schema=None,
        identity=("missing",),
        fields=(alias_field, other_field),
        accessor="projection_table",
        field_map={"py_name": alias_field, "other": other_field},
        exposed=True,
        redacted_fields=frozenset(),
    )
    rendered = projection(info)
    assert '"db_name" AS "py_name"' in rendered
    order_clause = identity_order_clause(info)
    assert order_clause == '"db_name", "other"'

    info_identity = ModelInfo(
        model=_TestAdminModel,
        table="projection_identity",
        scope="admin",
        schema=None,
        identity=("py_name",),
        fields=(alias_field,),
        accessor="projection_identity",
        field_map={"py_name": alias_field},
        exposed=True,
        redacted_fields=frozenset(),
    )
    assert identity_order_clause(info_identity) == '"db_name"'

    info_no_identity = ModelInfo(
        model=_TestAdminModel,
        table="projection_no_identity",
        scope="admin",
        schema=None,
        identity=(),
        fields=(alias_field,),
        accessor="projection_no_identity",
        field_map={"py_name": alias_field},
        exposed=True,
        redacted_fields=frozenset(),
    )
    assert identity_order_clause(info_no_identity) == '"db_name"'


def test_render_literal_date_and_time() -> None:
    date_value = dt.date(2024, 1, 1)
    time_value = dt.time(12, 30, 0, 123456)
    assert render_literal(date_value) == "'2024-01-01'::date"
    assert render_literal(time_value) == "'12:30:00.123456'::time"


def test_model_declared_models_includes_new_subclass() -> None:
    @model(scope=ModelScope.ADMIN, table="declared_models_demo")
    class DeclaredDemo(Model):  # type: ignore[misc, valid-type]
        id: str

    models = Model.declared_models()
    assert DeclaredDemo in models


def test_cli_migrate_scope_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "tests.cli_scope_admin_env"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    events: list[str] = []

    def record(context: MigrationContext) -> None:
        events.append(context.schema)

    module.get_database = lambda: database  # type: ignore[attr-defined]
    module.TENANTS = []  # type: ignore[attr-defined]
    module.MIGRATIONS = [  # type: ignore[attr-defined]
        Migration(name="cli_scope_admin", scope=MigrationScope.ADMIN, operations=(record,)),
    ]
    module.INCLUDE_MODEL_MIGRATIONS = False  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        assert cli_main(["migrate", "--module", module_name, "--scope", "admin"]) == 0
    finally:
        sys.modules.pop(module_name, None)
    assert events == [database.config.admin_schema]


def test_cli_make_migration_existing_file(tmp_path: Path) -> None:
    output_dir = tmp_path / "migrations"
    output_dir.mkdir()
    existing = output_dir / "existing.py"
    existing.write_text("", encoding="utf-8")
    with pytest.raises(SystemExit):
        cli_main(
            [
                "make-migration",
                "Existing",
                "--directory",
                str(output_dir),
            ]
        )


def test_render_migration_template_empty_models() -> None:
    content = _render_migration_template("demo", [], [])
    assert "Add Migration" in content
    imports = [line for line in content.splitlines() if line.startswith("from ")]
    assert imports == [
        "from __future__ import annotations",
        "from mere.migrations import Migration, MigrationScope, create_table_for_model",
    ]


def test_render_migration_template_only_admin_models(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Model, "declared_models", classmethod(lambda cls: (_TestAdminModel,)))
    content = _render_migration_template("only_admin", [_TestAdminModel], [])
    assert "create_table_for_model(_TestAdminModel)" in content
    assert "_tenant" not in content


def test_load_environment_prefers_callables(monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "tests.env_callables"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    module.get_database = lambda: database  # type: ignore[attr-defined]
    module.get_tenants = lambda: [tenant]  # type: ignore[attr-defined]

    def get_migrations() -> list[Migration]:
        return [
            Migration(
                name="callable",
                scope=MigrationScope.ADMIN,
                operations=(run_sql("SELECT 1"),),
            )
        ]

    module.get_migrations = get_migrations  # type: ignore[attr-defined]
    module.INCLUDE_MODEL_MIGRATIONS = False  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        env = _load_environment(module_name)
    finally:
        sys.modules.pop(module_name, None)
    assert env.database is database
    assert env.tenants == [tenant]
    assert [migration.name for migration in env.migrations] == ["callable"]


def test_load_environment_requires_database() -> None:
    module_name = "tests.env_missing_database"
    module = types.ModuleType(module_name)
    module.TENANTS = []  # type: ignore[attr-defined]
    module.MIGRATIONS = []  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        with pytest.raises(SystemExit):
            _load_environment(module_name)
    finally:
        sys.modules.pop(module_name, None)


def test_load_environment_uses_attribute_lists() -> None:
    module_name = "tests.env_attribute_lists"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")
    module.DATABASE = database  # type: ignore[attr-defined]
    module.TENANTS = [tenant]  # type: ignore[attr-defined]
    module.MIGRATIONS = [  # type: ignore[attr-defined]
        Migration(name="attr_env", scope=MigrationScope.ADMIN, operations=(run_sql("SELECT 1"),)),
    ]
    module.INCLUDE_MODEL_MIGRATIONS = False  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        env = _load_environment(module_name)
    finally:
        sys.modules.pop(module_name, None)
    assert env.tenants == [tenant]
    assert [migration.name for migration in env.migrations] == ["attr_env"]


def test_load_environment_defaults_without_tenants(monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "tests.env_defaults"
    module = types.ModuleType(module_name)
    connection = FakeConnection()
    connection.queue_result([])
    database = _database_with_connection(connection)
    module.get_database = lambda: database  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        env = _load_environment(module_name)
    finally:
        sys.modules.pop(module_name, None)
    assert env.tenants == []
    assert env.migrations  # defaults include generated migrations


def test_models_by_scope_filters_models(monkeypatch: pytest.MonkeyPatch) -> None:
    class Plain(Model):
        id: str

    @model(scope=ModelScope.TENANT, table="models_by_scope")
    class ScopedTenant(Model):  # type: ignore[misc, valid-type]
        id: str

    class Undecorated(Model):
        id: str

    plain_field = FieldInfo(
        name="id",
        column="id",
        python_type=str,
        has_default=False,
        default=msgspec.UNSET,
        default_factory=None,
    )
    setattr(
        Plain,
        "__model_info__",
        ModelInfo(
            model=Plain,
            table="plain_table",
            scope="custom",
            schema=None,
            identity=("id",),
            fields=(plain_field,),
            accessor="plain_table",
            field_map={"id": plain_field},
            exposed=True,
            redacted_fields=frozenset(),
        ),
    )

    monkeypatch.setattr(
        Model,
        "declared_models",
        classmethod(lambda cls: (Plain, ScopedTenant, _TestAdminModel, Undecorated)),
    )
    admin_models, tenant_models = _models_by_scope()
    assert ScopedTenant in tenant_models
    assert _TestAdminModel in admin_models
    assert Plain not in admin_models and Plain not in tenant_models
