import pytest

from mere.application import MereApp
from mere.config import AppConfig
from mere.database import Database, DatabaseConfig, PoolConfig
from mere.requests import Request
from mere.tenancy import TenantResolver
from tests.support import FakeConnection, FakePool


@pytest.mark.asyncio
async def test_application_wires_database_and_orm() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://demo"), admin_schema="admin")
    database = Database(db_config, pool=pool)
    config = AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",), database=db_config)
    app = MereApp(config=config, database=database)

    assert app.database is database
    assert app.orm is not None

    request = Request(
        method="GET",
        path="/",
        tenant=TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme",)).context_for("acme"),
    )
    scope = app.dependencies.scope(request)
    resolved_db = await scope.get(Database)
    assert resolved_db is database

    await app.startup()
    await app.shutdown()
    assert pool.closed
