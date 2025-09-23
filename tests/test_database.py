from typing import Any, Mapping

import pytest

import artemis.database as database_module
from artemis.database import (
    Database,
    DatabaseConfig,
    DatabaseConnection,
    DatabaseError,
    DatabaseResult,
    PoolConfig,
    _quote_identifier,
)
from artemis.tenancy import TenantResolver
from tests.support import FakeConnection, FakePool


@pytest.mark.asyncio
async def test_database_sets_search_path_and_role() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    config = DatabaseConfig(
        pool=PoolConfig(dsn="postgres://demo"),
        admin_schema="admin_core",
        tenant_schema_template="tenant_{tenant}",
        search_path=("public", "extensions"),
        default_role="app_role",
    )
    database = Database(config, pool=pool)

    async with database.connection() as _:
        pass

    assert connection.calls[0][1].startswith("SET search_path TO")
    assert '"admin_core"' in connection.calls[0][1]
    assert '"extensions"' in connection.calls[0][1]
    assert connection.calls[1][1] == 'SET ROLE "app_role"'

    connection.calls.clear()
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = resolver.context_for("acme")

    async with database.connection(tenant=tenant) as _:
        pass

    assert connection.calls[0][1].startswith("SET search_path TO")
    assert '"tenant_acme"' in connection.calls[0][1]


@pytest.mark.asyncio
async def test_database_schema_resolution_and_pool_factory() -> None:
    captured_options: list[dict[str, object]] = []

    def factory(options: Mapping[str, Any]) -> FakePool:
        captured_options.append(dict(options))
        return FakePool()

    config = DatabaseConfig(
        pool=PoolConfig(dsn="postgres://demo", options={"application_name": "artemis"}),
        admin_schema="admin",
        tenant_schema_template="tenant_{tenant}",
        tenant_schema_overrides={"beta": "custom_beta"},
    )
    database = Database(config, pool_factory=factory)
    await database.startup()
    assert captured_options[0]["dsn"] == "postgres://demo"
    assert captured_options[0]["application_name"] == "artemis"

    admin_info = type("AdminInfo", (), {"scope": "admin", "schema": None, "table": "billing"})
    tenant_info = type("TenantInfo", (), {"scope": "tenant", "schema": None, "table": "users"})
    tenant_override = type("TenantInfo", (), {"scope": "tenant", "schema": "tenant_{tenant}", "table": "users"})

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    acme = resolver.context_for("acme")
    beta = resolver.context_for("beta")

    assert database.schema_for_model(admin_info, None) == "admin"
    assert database.schema_for_model(tenant_info, acme) == "tenant_acme"
    assert database.schema_for_model(tenant_override, acme) == "tenant_acme"
    assert database.schema_for_model(tenant_info, beta) == "custom_beta"

    with pytest.raises(Exception):
        database.schema_for_model(tenant_info, None)

    await database.shutdown()
    assert database._pool is None  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_database_connection_helpers() -> None:
    raw = FakeConnection()
    connection = DatabaseConnection(raw)
    raw.queue_result([{"value": 1}])
    rows = await connection.fetch_all("SELECT 1")
    assert rows[0]["value"] == 1
    raw.queue_result([{"value": 2}])
    assert await connection.fetch_one("SELECT 2") == {"value": 2}
    raw.queue_result([{"value": 3}])
    assert await connection.fetch_value("SELECT 3") == 3
    await connection.execute_batch("SET search_path TO public")
    assert raw.calls[-1][0] == "execute_batch"
    assert connection.raw() is raw


def test_database_result_helpers() -> None:
    result = DatabaseResult(rows=[{"answer": 42}])
    assert result.first() == {"answer": 42}
    assert result.scalar() == 42
    empty = DatabaseResult(rows=[])
    assert empty.first() is None
    assert empty.scalar() is None


@pytest.mark.asyncio
async def test_database_connection_role_override() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://"), admin_schema="admin")
    database = Database(config, pool=pool)
    async with database.connection(role="analytics"):
        pass
    assert connection.calls[1][1] == 'SET ROLE "analytics"'

    await database.shutdown()
    # coverage branch: shutdown when pool already cleared
    await database.shutdown()


@pytest.mark.asyncio
async def test_database_shutdown_branches() -> None:
    class AcquireOnlyPool:
        def __init__(self) -> None:
            self._connection = FakeConnection()

        class _Context:
            def __init__(self, conn: FakeConnection) -> None:
                self._conn = conn

            async def __aenter__(self) -> FakeConnection:
                return self._conn

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

        def acquire(self) -> "AcquireOnlyPool._Context":
            return self._Context(self._connection)

    class AsyncClosingPool(AcquireOnlyPool):
        def __init__(self) -> None:
            super().__init__()
            self.closed = False

        async def close(self) -> None:
            self.closed = True

    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://"))
    no_close = AcquireOnlyPool()
    database = Database(config, pool=no_close)
    await database.shutdown()
    assert database._pool is None  # type: ignore[attr-defined]

    async_pool = AsyncClosingPool()
    database = Database(config, pool=async_pool)
    await database.shutdown()
    assert async_pool.closed is True


def test_database_private_helpers() -> None:
    config = DatabaseConfig(
        pool=PoolConfig(dsn="postgres://"),
        search_path=("tenant_acme", "public", "admin", "extensions"),
        tenant_schema_template="tenant_{tenant}",
        admin_schema="admin",
    )
    database = Database(config, pool=FakePool())
    tenant_resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",))
    tenant = tenant_resolver.context_for("acme")
    path = database._search_path(None, tenant)
    assert path[0] == "tenant_acme"
    # admin schema should not be duplicated in the search path
    assert path.count("admin") == 1
    assert path[-1] == "extensions"

    explicit = database._search_path("analytics", None)
    assert explicit[0] == "analytics"
    assert "public" in explicit

    with pytest.raises(DatabaseError):
        database._pool = None
        database._pool_factory = None  # type: ignore[assignment]
        database._ensure_pool()

    pool_config = PoolConfig(dsn="postgres://", application_name="demo", options={"extra": "value"})
    options = database_module._pool_kwargs(pool_config)
    assert options["dsn"] == "postgres://"
    assert options["application_name"] == "demo"
    assert options["extra"] == "value"
    assert options["options"]["extra"] == "value"

    assert _quote_identifier("tenant") == '"tenant"'
    assert _quote_identifier('acme"corp') == '"acme""corp"'

    assert database_module._coerce_rows(None) == []
    assert database_module._coerce_rows({"id": 1}) == [{"id": 1}]

    class Nullish:
        def result(self) -> None:
            return None

    assert database_module._coerce_rows(Nullish()) == []
    with pytest.raises(DatabaseError):
        database_module._coerce_rows(123)
