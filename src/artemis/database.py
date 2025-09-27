"""PostgreSQL database integration built on top of :mod:`psqlpy`."""

from __future__ import annotations

import inspect
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Mapping, Protocol, Sequence

import msgspec

from .tenancy import TenantContext

try:  # pragma: no cover - optional import exercised in runtime integration tests
    from psqlpy import ConnectionPool as _PsqlpyConnectionPool
except ModuleNotFoundError:  # pragma: no cover - fallback used in unit tests where a fake pool is injected
    _PsqlpyConnectionPool = None  # type: ignore[assignment]


class DatabaseError(RuntimeError):
    """Raised when the database integration cannot satisfy an operation."""


PoolFactory = Callable[[Mapping[str, Any]], Any]


class SecretRef(msgspec.Struct, frozen=True, omit_defaults=True):
    """Location of a secret managed outside the application."""

    provider: str
    name: str
    version: str | None = None


class SecretResolver(Protocol):
    """Resolve secret references into concrete values."""

    def resolve(self, secret: SecretRef) -> str: ...


class SecretValue(msgspec.Struct, frozen=True, omit_defaults=True):
    """String material sourced either inline or from a secret manager."""

    secret: SecretRef | None = None
    literal: str | None = None

    def resolve(self, resolver: "SecretResolver | None", *, field: str) -> str | None:
        if self.secret is not None:
            if resolver is None:
                raise DatabaseError(f"Secret resolver required for {field}")
            value = resolver.resolve(self.secret)
            if not isinstance(value, str):
                raise DatabaseError(f"Secret resolver returned non-string value for {field}")
            return value
        return self.literal


class DatabaseCredentials(msgspec.Struct, frozen=True, omit_defaults=True):
    """Database authentication material."""

    username: SecretValue | None = None
    password: SecretValue | None = None

    def resolve(self, resolver: "SecretResolver | None") -> Mapping[str, str]:
        credentials: dict[str, str] = {}
        if self.username is not None:
            value = self.username.resolve(resolver, field="credentials.username")
            if value is not None:
                credentials["user"] = value
        if self.password is not None:
            value = self.password.resolve(resolver, field="credentials.password")
            if value is not None:
                credentials["password"] = value
        return credentials


class TLSConfig(msgspec.Struct, frozen=True, omit_defaults=True):
    """Transport encryption configuration for PostgreSQL connections."""

    mode: str = "verify-full"
    ca_certificate: SecretValue | None = None
    client_certificate: SecretValue | None = None
    client_key: SecretValue | None = None
    client_key_password: SecretValue | None = None
    server_name: str | None = None
    certificate_pins: tuple[str, ...] = ()
    minimum_version: str | None = None
    maximum_version: str | None = None

    def resolve(self, resolver: "SecretResolver | None") -> Mapping[str, Any]:
        if not self.mode:
            return {}
        options: dict[str, Any] = {"sslmode": self.mode}
        sources = [
            (self.ca_certificate, "sslrootcert", "tls.ca_certificate"),
            (self.client_certificate, "sslcert", "tls.client_certificate"),
            (self.client_key, "sslkey", "tls.client_key"),
            (self.client_key_password, "sslpassword", "tls.client_key_password"),
        ]
        for source, option_key, field in sources:
            if source is None:
                continue
            value = source.resolve(resolver, field=field)
            if value is not None:
                options[option_key] = value
        if self.server_name:
            options["ssl_server_name"] = self.server_name
        if self.certificate_pins:
            options["ssl_cert_pins"] = tuple(self.certificate_pins)
        if self.minimum_version:
            options["ssl_min_protocol_version"] = self.minimum_version
        if self.maximum_version:
            options["ssl_max_protocol_version"] = self.maximum_version
        return options


class PoolConfig(msgspec.Struct, frozen=True, omit_defaults=True):
    """Configuration values passed to :class:`psqlpy.ConnectionPool`."""

    dsn: str | None = None
    host: str | None = None
    port: int | None = None
    db_name: str | None = None
    application_name: str | None = "artemis"
    max_db_pool_size: int = 10
    options: dict[str, str] = msgspec.field(default_factory=dict)
    connect_timeout_sec: int | None = None
    tcp_user_timeout_sec: int | None = None
    credentials: DatabaseCredentials = DatabaseCredentials()
    tls: TLSConfig = TLSConfig()


class DatabaseConfig(msgspec.Struct, frozen=True):
    """High level configuration for :class:`Database`."""

    pool: PoolConfig = PoolConfig()
    admin_schema: str = "admin"
    tenant_schema_template: str = "tenant_{tenant}"
    tenant_schema_overrides: dict[str, str] = msgspec.field(default_factory=dict)
    search_path: tuple[str, ...] = ("public",)
    default_role: str | None = None

    def schema_for_tenant(self, tenant: TenantContext) -> str:
        """Return the schema name for ``tenant``."""

        return self.tenant_schema_overrides.get(
            tenant.tenant,
            self.tenant_schema_template.format(tenant=tenant.tenant),
        )


@dataclass(slots=True)
class DatabaseResult:
    """Normalized representation of a query result."""

    rows: list[dict[str, Any]]

    def first(self) -> dict[str, Any] | None:
        return self.rows[0] if self.rows else None

    def scalar(self) -> Any:
        row = self.first()
        if not row:
            return None
        return next(iter(row.values()))


class DatabaseConnection:
    """Thin wrapper adding ergonomic helpers to a raw psqlpy connection."""

    def __init__(self, raw_connection: Any) -> None:
        self._raw = raw_connection

    async def execute(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        *,
        prepared: bool = False,
    ) -> DatabaseResult:
        payload = parameters if parameters is not None else None
        result = await self._raw.execute(query, payload, prepared=prepared)
        return DatabaseResult(_coerce_rows(result))

    async def execute_batch(self, query: str) -> None:
        await self._raw.execute_batch(query)

    async def fetch_all(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        *,
        prepared: bool = False,
    ) -> list[dict[str, Any]]:
        return (await self.execute(query, parameters, prepared=prepared)).rows

    async def fetch_one(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        *,
        prepared: bool = False,
    ) -> dict[str, Any] | None:
        return (await self.execute(query, parameters, prepared=prepared)).first()

    async def fetch_value(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        *,
        prepared: bool = False,
    ) -> Any:
        return (await self.execute(query, parameters, prepared=prepared)).scalar()

    async def set_search_path(self, schemas: Sequence[str]) -> None:
        quoted = ", ".join(_quote_identifier(name) for name in schemas)
        await self.execute(f"SET search_path TO {quoted}")

    async def set_role(self, role: str | None) -> None:
        if role is None:
            return
        await self.execute(f"SET ROLE {_quote_identifier(role)}")

    def raw(self) -> Any:
        """Expose the underlying connection for advanced callers."""

        return self._raw


class Database:
    """Tenant aware database helper that understands Artemis model metadata."""

    def __init__(
        self,
        config: DatabaseConfig,
        *,
        pool: Any | None = None,
        pool_factory: Callable[[Mapping[str, Any]], Any] | None = None,
        secret_resolver: "SecretResolver | None" = None,
    ) -> None:
        self.config = config
        self._pool = pool
        self._pool_factory = pool_factory or _default_pool_factory
        self._secret_resolver = secret_resolver

    async def startup(self) -> None:
        """Instantiate the underlying :class:`psqlpy.ConnectionPool` if needed."""

        self._ensure_pool()

    async def shutdown(self) -> None:
        """Dispose the connection pool."""

        if self._pool is None:
            return
        close = getattr(self._pool, "close", None)
        if close is None:
            self._pool = None
            return
        result = close()
        if inspect.isawaitable(result):  # pragma: no cover - depends on pool implementation
            await result
        self._pool = None

    @asynccontextmanager
    async def connection(
        self,
        *,
        tenant: TenantContext | None = None,
        schema: str | None = None,
        role: str | None = None,
    ) -> AsyncIterator[DatabaseConnection]:
        pool = self._ensure_pool()
        async with pool.acquire() as raw_connection:
            connection = DatabaseConnection(raw_connection)
            await connection.set_search_path(self._search_path(schema, tenant))
            await connection.set_role(role or self.config.default_role)
            yield connection

    @asynccontextmanager
    async def connection_for_model(
        self,
        model_info: "ModelInfo[Any]",
        *,
        tenant: TenantContext | None = None,
        role: str | None = None,
    ) -> AsyncIterator[DatabaseConnection]:
        schema = self.schema_for_model(model_info, tenant)
        async with self.connection(tenant=tenant, schema=schema, role=role) as connection:
            yield connection

    def schema_for_model(self, model_info: "ModelInfo[Any]", tenant: TenantContext | None) -> str:
        if model_info.scope == "admin":
            return model_info.schema or self.config.admin_schema
        if tenant is None:
            raise DatabaseError("tenant context required for tenant scoped model access")
        base = model_info.schema or self.config.schema_for_tenant(tenant)
        return base.format(tenant=tenant.tenant)

    def _ensure_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        if self._pool_factory is None:
            raise DatabaseError("No pool factory configured")
        options = _pool_kwargs(self.config.pool, resolver=self._secret_resolver)
        self._pool = self._pool_factory(options)
        return self._pool

    def _search_path(self, schema: str | None, tenant: TenantContext | None) -> tuple[str, ...]:
        path: list[str] = []
        if schema is not None:
            path.append(schema)
        elif tenant is not None:
            path.append(self.config.schema_for_tenant(tenant))
        else:
            path.append(self.config.admin_schema)
        for entry in self.config.search_path:
            if entry not in path:
                path.append(entry)
        return tuple(path)


def _coerce_rows(result: Any) -> list[dict[str, Any]]:
    if result is None:
        return []
    if hasattr(result, "result"):
        data = result.result()
    else:
        data = result
    if isinstance(data, list):
        return [dict(row) for row in data]
    if isinstance(data, dict):
        return [dict(data)]
    if data is None:
        return []
    raise DatabaseError(f"Unexpected query result type: {type(data)!r}")


def _pool_kwargs(config: PoolConfig, *, resolver: "SecretResolver | None" = None) -> Mapping[str, Any]:
    builtins = msgspec.to_builtins(config)
    # ``options`` is merged both nested and flattened for backward compatibility.
    raw_options = dict(builtins.pop("options", {}))
    builtins.pop("credentials", None)
    builtins.pop("tls", None)

    payload: dict[str, Any] = {key: value for key, value in builtins.items() if value is not None}
    payload.update(config.options)
    nested_options: dict[str, Any] = {**raw_options, **config.options}

    credentials = config.credentials.resolve(resolver)
    payload.update(credentials)

    tls_options = config.tls.resolve(resolver)
    payload.update(tls_options)
    for key, value in tls_options.items():
        nested_options[key] = value

    payload["options"] = nested_options
    return {key: value for key, value in payload.items() if value is not None}


def _default_pool_factory(options: Mapping[str, Any]) -> Any:  # pragma: no cover - exercised in integration
    if _PsqlpyConnectionPool is None:
        raise DatabaseError("psqlpy is not installed; install psqlpy to use the default pool")
    return _PsqlpyConnectionPool(**options)


def _quote_identifier(identifier: str) -> str:
    escaped = identifier.replace('"', '""')
    return f'"{escaped}"'


__all__ = [
    "Database",
    "DatabaseConfig",
    "DatabaseConnection",
    "DatabaseCredentials",
    "DatabaseError",
    "DatabaseResult",
    "PoolConfig",
    "SecretRef",
    "SecretResolver",
    "SecretValue",
    "TLSConfig",
    "_quote_identifier",
]


if False:  # pragma: no cover - import cycle hints for type checkers
    from .orm import ModelInfo
