# Database and ORM

Mere provides a tenant-aware database layer coupled with a declarative ORM. Models define schema
metadata and scopes (admin vs tenant) to keep data separated safely.

## Connecting to Postgres

```python
from mere import AppConfig, MereApp
from mere.database import Database, DatabaseConfig

config = AppConfig(
    site="demo",
    domain="local.test",
    allowed_tenants=("acme",),
    database=Database(DatabaseConfig.from_dsn("postgresql://user:pass@localhost/db")),
)
app = MereApp(config)
```

The database helper manages connection pools per-tenant and exposes async helpers for executing SQL
with msgspec-typed results.

## Defining models

```python
from mere.orm import Model, ModelScope, model

@model(scope=ModelScope.TENANT, tablename="widgets")
class Widget(Model):
    id: int
    name: str
```

Models register with the global registry so migrations and the ORM can discover them automatically.
Tenant-scoped models are automatically namespaced by tenant when issuing queries.

## Running migrations

Invoke the CLI to generate and apply migrations:

```shell
uv run mere make-migration add_widgets --directory=migrations
uv run mere migrate --module=migrations
```

`generate_schema_migrations` introspects the registered models to create idempotent migrations for both
tenant and admin schemas.
