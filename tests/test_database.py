from typing import Any, Mapping, cast

import pytest

import mere.database as database_module
from mere.database import (
    Database,
    DatabaseConfig,
    DatabaseConnection,
    DatabaseCredentials,
    DatabaseError,
    DatabaseResult,
    PoolConfig,
    SecretRef,
    SecretValue,
    TLSConfig,
    _quote_identifier,
)
from mere.tenancy import TenantResolver
from tests.support import FakeConnection, FakePool, StaticSecretResolver


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
    captured_options: list[dict[str, Any]] = []

    def factory(options: Mapping[str, Any]) -> FakePool:
        captured_options.append(dict(options))
        return FakePool()

    config = DatabaseConfig(
        pool=PoolConfig(dsn="postgres://demo", options={"application_name": "mere"}),
        admin_schema="admin",
        tenant_schema_template="tenant_{tenant}",
        tenant_schema_overrides={"beta": "custom_beta"},
    )
    database = Database(config, pool_factory=factory)
    await database.startup()
    assert captured_options[0]["dsn"] == "postgres://demo"
    assert captured_options[0]["application_name"] == "mere"
    assert captured_options[0]["sslmode"] == "verify-full"
    assert captured_options[0]["options"]["sslmode"] == "verify-full"

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


def test_pool_kwargs_resolves_secrets_and_tls() -> None:
    resolver = StaticSecretResolver(
        {
            ("vault", "db-user", None): "appuser",
            ("vault", "db-password", None): "s3cr3t",
            ("vault", "db-ca", None): "/etc/db-ca.pem",
            ("vault", "client-cert", None): "/etc/db-cert.pem",
            ("vault", "client-key", None): "/etc/db-key.pem",
            ("vault", "client-key-password", None): "passphrase",
        }
    )
    pool_config = PoolConfig(
        dsn="postgres://secure",
        credentials=DatabaseCredentials(
            username=SecretValue(secret=SecretRef(provider="vault", name="db-user")),
            password=SecretValue(secret=SecretRef(provider="vault", name="db-password")),
        ),
        tls=TLSConfig(
            ca_certificate=SecretValue(secret=SecretRef(provider="vault", name="db-ca")),
            certificate_pins=("sha256:abcdef",),
            client_certificate=SecretValue(secret=SecretRef(provider="vault", name="client-cert")),
            client_key=SecretValue(secret=SecretRef(provider="vault", name="client-key")),
            client_key_password=SecretValue(secret=SecretRef(provider="vault", name="client-key-password")),
            server_name="db.internal",
            minimum_version="TLS1.2",
            maximum_version="TLS1.3",
        ),
    )
    options = database_module._pool_kwargs(pool_config, resolver=resolver)
    assert options["user"] == "appuser"
    assert options["password"] == "s3cr3t"
    assert options["sslrootcert"] == "/etc/db-ca.pem"
    assert options["sslcert"] == "/etc/db-cert.pem"
    assert options["sslkey"] == "/etc/db-key.pem"
    assert options["sslpassword"] == "passphrase"
    assert options["ssl_server_name"] == "db.internal"
    assert options["ssl_min_protocol_version"] == "TLS1.2"
    assert options["ssl_max_protocol_version"] == "TLS1.3"
    assert options["ssl_cert_pins"] == ("sha256:abcdef",)
    assert options["sslmode"] == "verify-full"
    assert resolver.calls  # ensure secrets were fetched


def test_secret_value_requires_resolver() -> None:
    secret = SecretValue(secret=SecretRef(provider="vault", name="db-user"))
    with pytest.raises(DatabaseError):
        secret.resolve(None, field="credentials.username")


def test_secret_value_requires_string() -> None:
    class Resolver:
        def resolve(self, _: SecretRef) -> str:
            return cast(str, 123)

    secret = SecretValue(secret=SecretRef(provider="vault", name="db-user"))
    with pytest.raises(DatabaseError):
        secret.resolve(
            cast(database_module.SecretResolver, Resolver()),
            field="credentials.username",
        )


def test_tls_config_disabled_mode() -> None:
    tls = TLSConfig(mode="")
    assert tls.resolve(None) == {}


def test_tls_config_skips_empty_values() -> None:
    tls = TLSConfig(client_certificate=SecretValue(literal=None))
    assert "sslcert" not in tls.resolve(None)


def test_secret_value_returns_literal() -> None:
    secret = SecretValue(literal="inline")
    assert secret.resolve(None, field="credentials.username") == "inline"


def test_database_credentials_skip_none_values() -> None:
    credentials = DatabaseCredentials(
        username=SecretValue(literal=None),
        password=SecretValue(literal=None),
    )
    assert credentials.resolve(None) == {}


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
    assert options["sslmode"] == "verify-full"
    assert options["options"]["sslmode"] == "verify-full"

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
