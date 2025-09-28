# Tenant routing

Mere enforces tenant isolation by threading an explicit `TenantContext` through every boundary. The
context captures the tenant slug, scope (tenant vs admin), and additional metadata that downstream
services can use.

## Host-based resolution

`TenantResolver` maps hostnames to tenants. Given a site `demo` and domain `local.test`, a request to
`https://acme.demo.local.test` resolves to the `acme` tenant while `https://admin.demo.local.test`
yields the admin scope. The resolver rejects unknown hosts to prevent cross-tenant data leaks.

## Using tenant context

Handlers access the active tenant through dependency injection:

```python
from mere.routing import get
from mere.tenancy import TenantContext

@get("/me")
async def my_profile(tenant: TenantContext) -> dict[str, str]:
    return {"tenant": tenant.tenant}
```

Database utilities such as `Database` and `ORM` expect the context when issuing queries so tables are
segregated by tenant. Background jobs and events should propagate the context explicitly to keep work
bounded to the original tenant.
