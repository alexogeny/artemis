from __future__ import annotations

import pytest

from artemis.dependency import DependencyProvider, DependencyScope
from artemis.requests import Request
from artemis.tenancy import TenantContext, TenantScope


@pytest.mark.asyncio
async def test_dependency_scope_resolves_nested_dependencies() -> None:
    provider = DependencyProvider()
    calls: dict[str, int] = {"count": 0}

    @provider.register(int)
    async def provide_number(context: TenantContext) -> int:
        calls["count"] += 1
        return 1 if context.tenant == "acme" else 2

    @provider.register(str)
    def provide_message(value: int) -> str:
        return f"value={value}"

    request = Request(
        method="GET",
        path="/",
        tenant=TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
    )
    scope = provider.scope(request)

    message = await scope.get(str)
    assert message == "value=1"
    # Cached dependency is reused
    assert await scope.get(int) == 1
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_missing_dependency_raises_lookup() -> None:
    provider = DependencyProvider()
    request = Request(
        method="GET",
        path="/",
        tenant=TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
    )
    scope = provider.scope(request)
    with pytest.raises(LookupError):
        await scope.get(float)


@pytest.mark.asyncio
async def test_dependency_factory_requires_annotations() -> None:
    provider = DependencyProvider()

    @provider.register(int)
    def missing_annotation(value) -> int:  # type: ignore[no-untyped-def]
        return 1

    request = Request(
        method="GET",
        path="/",
        tenant=TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
    )
    scope = provider.scope(request)
    with pytest.raises(TypeError):
        await scope.get(int)


@pytest.mark.asyncio
async def test_scope_missing_provider_direct() -> None:
    request = Request(
        method="GET",
        path="/",
        tenant=TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
    )
    scope = DependencyScope({}, request)
    with pytest.raises(LookupError):
        await scope.get(str)


@pytest.mark.asyncio
async def test_scope_returns_request_and_tenant() -> None:
    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(method="GET", path="/", tenant=tenant)
    scope = DependencyScope({}, request)
    assert await scope.get(Request) is request
    assert await scope.get(TenantContext) is tenant


@pytest.mark.asyncio
async def test_dependency_factory_receives_request() -> None:
    provider = DependencyProvider()

    @provider.register(dict)
    async def provide_payload(request: Request) -> dict[str, str]:
        return {"path": request.path}

    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(method="GET", path="/payload", tenant=tenant)
    scope = provider.scope(request)
    payload = await scope.get(dict)
    assert payload == {"path": "/payload"}
