"""Schema migration tooling for Mere models."""

from __future__ import annotations

import asyncio
import datetime as dt
import enum
import inspect
import textwrap
import types
import uuid
from collections.abc import Mapping as MappingABC
from collections.abc import Sequence as SequenceABC
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable, Iterable, Sequence, Union, cast, get_args, get_origin

import msgspec
from msgspec import json as msgspec_json

from .database import Database, DatabaseConnection, _quote_identifier
from .orm import FieldInfo, Model, ModelInfo
from .tenancy import TenantContext


class MigrationError(RuntimeError):
    """Raised when migration execution fails."""


class MigrationScope(str, enum.Enum):
    """Scopes supported by migrations."""

    ADMIN = "admin"
    TENANT = "tenant"

    def __str__(self) -> str:  # pragma: no cover - convenience for logs
        return self.value


MigrationCallable = Callable[["MigrationContext"], Awaitable[None] | None]
TenantProvider = Callable[[], Awaitable[Sequence[TenantContext]] | Sequence[TenantContext]]


@dataclass(slots=True)
class MigrationContext:
    """Runtime context passed to migration operations."""

    database: Database
    connection: DatabaseConnection
    tenant: TenantContext | None
    schema: str

    async def execute(
        self,
        sql: str,
        parameters: Sequence[Any] | None = None,
        *,
        prepared: bool = False,
    ) -> None:
        await self.connection.execute(sql, list(parameters or []), prepared=prepared)

    async def fetch_all(
        self,
        sql: str,
        parameters: Sequence[Any] | None = None,
        *,
        prepared: bool = False,
    ) -> list[dict[str, Any]]:
        return await self.connection.fetch_all(sql, parameters, prepared=prepared)


@dataclass(slots=True)
class Migration:
    """Declarative description of a schema migration."""

    name: str
    scope: MigrationScope
    operations: tuple[MigrationCallable, ...]
    target_tenants: tuple[str, ...] | None = None
    schema: str | None = None
    background: bool = False

    async def apply(self, context: MigrationContext) -> None:
        for operation in self.operations:
            result = operation(context)
            if inspect.isawaitable(result):
                await result

    def runs_for(self, tenant: TenantContext | None) -> bool:
        if self.scope == MigrationScope.ADMIN:
            return tenant is None
        if tenant is None:
            return False
        if self.target_tenants is None:
            return True
        return tenant.tenant in self.target_tenants


class MigrationRunner:
    """Apply migrations across admin and tenant schemas."""

    def __init__(
        self,
        database: Database,
        *,
        migrations: Iterable[Migration] | None = None,
        tenant_provider: TenantProvider | None = None,
        tracking_table: str = "schema_migrations",
    ) -> None:
        self.database = database
        self._tenant_provider = tenant_provider
        self.tracking_table = tracking_table
        self._migrations: dict[str, Migration] = {}
        if migrations:
            for migration in migrations:
                self.add_migration(migration)

    def add_migration(self, migration: Migration) -> None:
        if migration.name in self._migrations:
            raise MigrationError(f"Migration '{migration.name}' already registered")
        self._migrations[migration.name] = migration

    def migrations(self) -> tuple[Migration, ...]:
        return tuple(self._migrations.values())

    async def run_all(
        self,
        *,
        scope: MigrationScope | None = None,
        tenants: Sequence[TenantContext] | None = None,
        background: bool | None = None,
    ) -> list[str]:
        await self._ensure_tracking_table()
        applied = await self._load_applied()
        executed: list[str] = []
        for migration in self._migrations.values():
            if scope is not None and migration.scope != scope:
                continue
            if background is not None and migration.background is not background:
                continue
            targets = await self._targets_for_migration(migration, tenants)
            for target in targets:
                tenant_name = target.tenant if target else None
                key = (migration.name, tenant_name)
                if key in applied:
                    continue
                await self._apply_migration(migration, target)
                applied.add(key)
                executed.append(self._execution_label(migration, target))
        return executed

    async def run_in_background(
        self,
        *,
        scope: MigrationScope | None = None,
        tenants: Sequence[TenantContext] | None = None,
        background: bool | None = None,
    ) -> asyncio.Task[list[str]]:
        loop = asyncio.get_running_loop()
        return loop.create_task(self.run_all(scope=scope, tenants=tenants, background=background))

    async def snapshot_test_data(
        self,
        destination: Path,
        *,
        tenants: Sequence[TenantContext],
        include_admin: bool = True,
    ) -> Path:
        statements: list[str] = []
        if include_admin:
            admin_rows = await self._snapshot_scope(MigrationScope.ADMIN, None)
            if admin_rows:
                statements.append("-- scope: admin")
                statements.extend(admin_rows)
        for tenant in sorted(tenants, key=lambda ctx: ctx.tenant):
            tenant_rows = await self._snapshot_scope(MigrationScope.TENANT, tenant)
            if tenant_rows:
                statements.append(f"-- tenant: {tenant.tenant}")
                statements.extend(tenant_rows)
        if not statements:
            destination.write_text("-- no data\n", encoding="utf-8")
        else:
            destination.write_text("\n".join(statements) + "\n", encoding="utf-8")
        return destination

    async def _snapshot_scope(
        self,
        scope: MigrationScope,
        tenant: TenantContext | None,
    ) -> list[str]:
        infos = _model_infos_for_scope(scope.value)
        if not infos:
            return []
        context_schema = self._schema_for_scope(scope, tenant, None)
        statements: list[str] = []
        tenant_ctx = tenant if scope == MigrationScope.TENANT else None
        async with self.database.connection(
            schema=context_schema,
            tenant=tenant_ctx,
        ) as connection:
            for info in infos:
                schema = _resolve_model_schema(info, context_schema, tenant)
                table = _qualified_table(schema, info.table)
                query = f"SELECT {projection(info)} FROM {table}"
                order_clause = identity_order_clause(info)
                if order_clause:
                    query += f" ORDER BY {order_clause}"
                rows = await connection.fetch_all(query)
                for row in rows:
                    statements.append(render_insert(schema, info, row))
        return statements

    async def _apply_migration(self, migration: Migration, tenant: TenantContext | None) -> None:
        context_schema = self._schema_for_scope(migration.scope, tenant, migration.schema)
        tenant_ctx = tenant if migration.scope == MigrationScope.TENANT else None
        async with self.database.connection(
            schema=context_schema,
            tenant=tenant_ctx,
        ) as connection:
            context = MigrationContext(
                database=self.database,
                connection=connection,
                tenant=tenant,
                schema=context_schema,
            )
            await migration.apply(context)
        await self._record_applied(migration, tenant)

    async def _ensure_tracking_table(self) -> None:
        schema = self.database.config.admin_schema
        statement = textwrap.dedent(
            f"""
            CREATE TABLE IF NOT EXISTS {_qualified_table(schema, self.tracking_table)} (
                migration_name TEXT NOT NULL,
                tenant TEXT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (migration_name, tenant)
            )
            """
        ).strip()
        async with self.database.connection(schema=schema) as connection:
            await connection.execute(statement)

    async def _load_applied(self) -> set[tuple[str, str | None]]:
        schema = self.database.config.admin_schema
        table = _qualified_table(schema, self.tracking_table)
        async with self.database.connection(schema=schema) as connection:
            rows = await connection.fetch_all(f"SELECT migration_name, tenant FROM {table}")
        return {(row["migration_name"], row.get("tenant")) for row in rows}

    async def _record_applied(self, migration: Migration, tenant: TenantContext | None) -> None:
        schema = self.database.config.admin_schema
        table = _qualified_table(schema, self.tracking_table)
        tenant_name = tenant.tenant if tenant else None
        async with self.database.connection(schema=schema) as connection:
            await connection.execute(
                f"INSERT INTO {table} (migration_name, tenant) VALUES ($1, $2)",
                [migration.name, tenant_name],
            )

    async def _targets_for_migration(
        self,
        migration: Migration,
        explicit: Sequence[TenantContext] | None,
    ) -> list[TenantContext | None]:
        if migration.scope == MigrationScope.ADMIN:
            return [None]
        if explicit is not None:
            tenants = list(explicit)
        else:
            tenants = list(await self._resolve_tenants())
        tenants.sort(key=lambda ctx: ctx.tenant)
        if migration.target_tenants is None:
            return cast(list[TenantContext | None], list(tenants))
        allowed = set(migration.target_tenants)
        filtered = [tenant for tenant in tenants if tenant.tenant in allowed]
        return cast(list[TenantContext | None], filtered)

    async def _resolve_tenants(self) -> Sequence[TenantContext]:
        if self._tenant_provider is None:
            return ()
        result = self._tenant_provider()
        if inspect.isawaitable(result):
            return await result
        return result

    def _schema_for_scope(
        self,
        scope: MigrationScope,
        tenant: TenantContext | None,
        explicit: str | None,
    ) -> str:
        if explicit is not None:
            if tenant is not None:
                return explicit.format(tenant=tenant.tenant)
            if "{tenant" in explicit:
                raise MigrationError("Tenant placeholder present but no tenant provided")
            return explicit
        if scope == MigrationScope.ADMIN:
            return self.database.config.admin_schema
        if tenant is None:
            raise MigrationError("Tenant context required for tenant migration")
        return self.database.config.schema_for_tenant(tenant)

    def _execution_label(self, migration: Migration, tenant: TenantContext | None) -> str:
        if tenant is None:
            return migration.name
        return f"{migration.name}:{tenant.tenant}"


def create_table_for_model(model: type[Model]) -> MigrationCallable:
    """Return an operation that issues a ``CREATE TABLE`` for ``model``."""

    info = getattr(model, "__model_info__", None)
    if info is None:
        raise MigrationError(f"Model {model.__name__} is missing registration metadata")

    async def operation(context: MigrationContext) -> None:
        statement = build_create_table_statement(context.schema, info, context.tenant)
        await context.execute(statement)

    return operation


def run_sql(statement: str) -> MigrationCallable:
    """Return an operation executing the provided SQL."""

    async def operation(context: MigrationContext) -> None:
        await context.execute(statement)

    return operation


def generate_schema_migrations(name_prefix: str = "bootstrap") -> list[Migration]:
    """Generate ``CREATE TABLE`` migrations for every declared model."""

    migrations: list[Migration] = []
    for scope in (MigrationScope.ADMIN, MigrationScope.TENANT):
        infos = _model_infos_for_scope(scope.value)
        if not infos:
            continue
        operations = tuple(create_table_for_model(info.model) for info in infos)
        migrations.append(
            Migration(
                name=f"{name_prefix}_{scope.value}",
                scope=scope,
                operations=operations,
            )
        )
    return migrations


def build_create_table_statement(
    context_schema: str,
    info: ModelInfo[Any],
    tenant: TenantContext | None,
) -> str:
    schema = _resolve_model_schema(info, context_schema, tenant)
    columns = [build_column_definition(field) for field in info.fields]
    if info.identity:
        parts = []
        for name in info.identity:
            field = info.field_map.get(name)
            if field is not None:
                parts.append(_quote_identifier(field.column))
        if parts:
            columns.append(f"PRIMARY KEY ({', '.join(parts)})")
    column_sql = ",\n    ".join(columns)
    return textwrap.dedent(
        f"""
        CREATE TABLE IF NOT EXISTS {_qualified_table(schema, info.table)} (
            {column_sql}
        )
        """
    ).strip()


def build_column_definition(field: FieldInfo) -> str:
    sql_type = sql_type_for(field.python_type)
    parts = [f"{_quote_identifier(field.column)} {sql_type}"]
    if not field.has_default:
        parts.append("NOT NULL")
    default_clause = render_default(field)
    if default_clause:
        parts.append(default_clause)
    return " ".join(parts)


def sql_type_for(python_type: Any) -> str:
    resolved = _normalize_python_type(python_type)
    if resolved is str:
        return "TEXT"
    if resolved is int:
        return "BIGINT"
    if resolved is float:
        return "DOUBLE PRECISION"
    if resolved is bool:
        return "BOOLEAN"
    if resolved is bytes:
        return "BYTEA"
    if resolved is dt.datetime:
        return "TIMESTAMPTZ"
    if resolved is dt.date:
        return "DATE"
    if resolved is dt.time:
        return "TIME"
    if resolved is uuid.UUID:
        return "UUID"
    if inspect.isclass(resolved) and issubclass(resolved, enum.Enum):
        return "TEXT"
    if resolved in {list, tuple, set, dict, SequenceABC, MappingABC}:
        return "JSONB"
    return "JSONB"


def _normalize_python_type(python_type: Any) -> Any:
    origin = get_origin(python_type)
    if origin is Annotated:
        return _normalize_python_type(get_args(python_type)[0])
    if origin in {Union, types.UnionType}:
        args = [arg for arg in get_args(python_type) if arg is not type(None)]
        if len(args) == 1:
            return _normalize_python_type(args[0])
        return object
    if origin is None:
        return python_type
    return origin


def render_default(field: FieldInfo) -> str:
    if field.default is msgspec.UNSET or field.default_factory is not None:
        return ""
    return f"DEFAULT {render_literal(field.default)}"


def projection(info: ModelInfo[Any]) -> str:
    parts: list[str] = []
    for field in info.fields:
        column = _quote_identifier(field.column)
        if field.column != field.name:
            alias = _quote_identifier(field.name)
            parts.append(f"{column} AS {alias}")
        else:
            parts.append(column)
    return ", ".join(parts)


def identity_order_clause(info: ModelInfo[Any]) -> str:
    columns: list[str] = []
    if info.identity:
        for name in info.identity:
            field = info.field_map.get(name)
            if field is not None:
                columns.append(_quote_identifier(field.column))
    if not columns:
        columns = [_quote_identifier(field.column) for field in info.fields]
    return ", ".join(columns)


def render_insert(schema: str, info: ModelInfo[Any], row: dict[str, Any]) -> str:
    qualified = _qualified_table(schema, info.table)
    columns = [_quote_identifier(field.column) for field in info.fields]
    values = [render_literal(row.get(field.name)) for field in info.fields]
    return f"INSERT INTO {qualified} ({', '.join(columns)}) VALUES ({', '.join(values)});"


def render_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dt.datetime):
        return f"'{value.isoformat()}'::timestamptz"
    if isinstance(value, dt.date):
        return f"'{value.isoformat()}'::date"
    if isinstance(value, dt.time):
        return f"'{value.isoformat()}'::time"
    if isinstance(value, enum.Enum):
        return render_literal(value.value)
    if isinstance(value, bytes):
        return "'\\x" + value.hex() + "'::bytea"
    if isinstance(value, (list, tuple, dict, set)):
        encoded = msgspec_json.encode(value, order="sorted").decode("utf-8")
        return f"'{encoded}'::jsonb"
    return "'" + str(value).replace("'", "''") + "'"


def _qualified_table(schema: str, table: str) -> str:
    return f"{_quote_identifier(schema)}.{_quote_identifier(table)}"


def _resolve_model_schema(
    info: ModelInfo[Any],
    context_schema: str,
    tenant: TenantContext | None,
) -> str:
    override = info.schema
    if override is None:
        return context_schema
    if tenant is None:
        if "{tenant" in override:
            raise MigrationError("Tenant placeholder present but no tenant provided")
        return override
    return override.format(tenant=tenant.tenant)


def _model_infos_for_scope(scope: str) -> list[ModelInfo[Any]]:
    infos: list[ModelInfo[Any]] = []
    for model in Model.declared_models():
        info = getattr(model, "__model_info__", None)
        if info is None or info.scope != scope:
            continue
        infos.append(info)
    infos.sort(key=lambda info: info.table)
    return infos


__all__ = [
    "Migration",
    "MigrationContext",
    "MigrationError",
    "MigrationRunner",
    "MigrationScope",
    "build_create_table_statement",
    "create_table_for_model",
    "generate_schema_migrations",
    "identity_order_clause",
    "projection",
    "render_insert",
    "render_literal",
    "run_sql",
]
