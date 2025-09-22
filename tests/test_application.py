from __future__ import annotations

from typing import Any, AsyncIterator, Awaitable, Callable

import msgspec
import pytest
import pytest_asyncio

from artemis.application import Artemis, ArtemisApp
from artemis.config import AppConfig
from artemis.dependency import DependencyProvider
from artemis.exceptions import HTTPError
from artemis.rbac import CedarEffect, CedarEngine, CedarEntity, CedarPolicy, CedarReference
from artemis.requests import Request
from artemis.responses import JSONResponse, Response
from artemis.routing import RouteGuard, get
from artemis.serialization import json_decode, json_encode
from artemis.tenancy import TenantContext
from artemis.testing import TestClient


class CreateItem(msgspec.Struct):
    name: str


class Pagination(msgspec.Struct):
    limit: int = 10
    offset: int = 0


class MissingDependency:
    """Sentinel type used to assert dependency error handling."""


class ItemStore:
    def __init__(self) -> None:
        self._items: dict[tuple[str, int], dict[str, Any]] = {
            ("acme", 1): {"id": 1, "name": "Rocket"},
            ("beta", 1): {"id": 1, "name": "Portal"},
        }

    async def fetch(self, tenant: str, item_id: int) -> dict[str, Any]:
        return dict(self._items[(tenant, item_id)])

    async def create(self, tenant: str, payload: CreateItem) -> dict[str, Any]:
        next_id = max((identifier for t, identifier in self._items if t == tenant), default=0) + 1
        record = {"id": next_id, "name": payload.name}
        self._items[(tenant, next_id)] = record
        return dict(record)

    async def tenant_ids(self) -> list[str]:
        return sorted({tenant for tenant, _ in self._items})


@pytest_asyncio.fixture
async def app() -> AsyncIterator[ArtemisApp]:
    provider = DependencyProvider()
    store = ItemStore()
    provider.provide(ItemStore, lambda: store)

    config = AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    application = ArtemisApp(config=config, dependency_provider=provider)

    @application.get("/items/{item_id}", name="get_item")
    async def read_item(item_id: int, store: ItemStore, tenant: TenantContext) -> dict[str, Any]:
        data = await store.fetch(tenant.tenant, item_id)
        return {"tenant": tenant.tenant, "item": data}

    @application.post("/items", name="create_item")
    async def create_item(payload: CreateItem, store: ItemStore, tenant: TenantContext) -> Response:
        record = await store.create(tenant.tenant, payload)
        return JSONResponse({"tenant": tenant.tenant, "item": record}, status=201)

    @application.post("/double")
    async def double(first: CreateItem, second: CreateItem) -> Response:
        return JSONResponse({"first": first.name, "second": second.name})

    @application.get("/admin/tenants", name="list_tenants")
    async def list_tenants(tenant: TenantContext, store: ItemStore) -> list[str]:
        if not tenant.is_admin:
            raise HTTPError(403, "admin scope required")
        return await store.tenant_ids()

    @application.get("/search")
    async def search(request: Request) -> dict[str, int]:
        params = request.query(Pagination)
        return {"limit": params.limit, "offset": params.offset}

    @application.get("/noop")
    async def noop() -> None:
        return None

    @application.get("/echo/{value}")
    async def echo(value):  # type: ignore[no-untyped-def]
        return {"value": value}

    @application.on_shutdown
    async def shutdown_async() -> None:
        return None

    try:
        yield application
    finally:
        await application.shutdown()


@pytest.mark.asyncio
async def test_tenant_isolation(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        acme = await client.get("/items/1", tenant="acme")
        beta = await client.get("/items/1", tenant="beta")
        assert json_decode(acme.body)["tenant"] == "acme"
        assert json_decode(beta.body)["tenant"] == "beta"


@pytest.mark.asyncio
async def test_body_parsing_and_creation(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        response = await client.post("/items", tenant="acme", json={"name": "Analyzer"})
        assert response.status == 201
        payload = json_decode(response.body)
        assert payload == {"tenant": "acme", "item": {"id": 2, "name": "Analyzer"}}


@pytest.mark.asyncio
async def test_admin_route_requires_admin_scope(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        admin = await client.get("/admin/tenants", tenant="admin")
        assert json_decode(admin.body) == ["acme", "beta"]
        forbidden = await client.get("/admin/tenants", tenant="acme")
        assert forbidden.status == 403
        payload = json_decode(forbidden.body)
        assert payload == {"error": {"status": 403, "detail": "admin scope required"}}


@pytest.mark.asyncio
async def test_query_parsing(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        response = await client.get("/search", tenant="acme", query={"limit": 5, "offset": 2})
        assert json_decode(response.body) == {"limit": 5, "offset": 2}


@pytest.mark.asyncio
async def test_url_generation(app: ArtemisApp) -> None:
    path = app.url_path_for("get_item", item_id=99)
    assert path == "/items/99"


@pytest.mark.asyncio
async def test_include_and_lifecycle_hooks() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    events: list[str] = []

    @app.on_startup
    async def startup_hook() -> None:
        events.append("startup")

    @app.on_startup
    def sync_startup() -> None:
        events.append("sync-startup")

    @app.on_shutdown
    def shutdown_hook() -> None:
        events.append("shutdown")

    @get("/health", name="health")
    def health() -> str:
        return "ok"

    app.include(health)

    async with TestClient(app) as client:
        default_response = await client.get("/health")
        assert default_response.body == b"ok"
        response = await client.get("/health", tenant="acme")
        assert response.body == b"ok"

    assert events == ["startup", "sync-startup", "shutdown"]
    with pytest.raises(LookupError):
        app.url_path_for("missing")


def test_artemis_from_config() -> None:
    dict_app = Artemis.from_config({"site": "prod", "domain": "example.com", "allowed_tenants": ("acme", "beta")})
    assert isinstance(dict_app, ArtemisApp)
    assert dict_app.config.site == "prod"
    assert dict_app.config.tenant_host("acme") == "acme.prod.example.com"

    config_app = Artemis.from_config(AppConfig(site="demo", domain="example.org", allowed_tenants=("acme", "beta")))
    assert isinstance(config_app, ArtemisApp)
    assert config_app.config.tenant_host(config_app.config.marketing_tenant) == "demo.example.org"


def test_include_requires_metadata() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    def handler() -> str:
        return "ok"

    with pytest.raises(ValueError):
        app.include(handler)


@pytest.mark.asyncio
async def test_route_guard_authorizes_with_cedar_engine() -> None:
    provider = DependencyProvider()
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "allowed"),
        actions=("items:read",),
        resource=CedarReference("item", "*"),
    )
    engine = CedarEngine([policy])
    provider.provide(CedarEngine, lambda: engine)

    app = ArtemisApp(
        AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")),
        dependency_provider=provider,
    )

    async def identity_middleware(
        request: Request, handler: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        user = request.header("x-user", "anonymous") or "anonymous"
        request.with_principal(CedarEntity(type="User", id=user))
        return await handler(request)

    app.add_middleware(identity_middleware)

    guard = RouteGuard(
        action="items:read",
        resource_type="item",
        resource_id=lambda request: request.path_params["item_id"],
        context_factory=lambda request: {"tenant": request.tenant.tenant},
    )

    @app.get("/secure/{item_id}", authorize=guard)
    async def secure(item_id: str) -> dict[str, str]:
        return {"item": item_id}

    async with TestClient(app) as client:
        success = await client.get("/secure/42", tenant="acme", headers={"x-user": "allowed"})
        assert success.status == 200
        assert json_decode(success.body) == {"item": "42"}
        forbidden = await client.get("/secure/42", tenant="acme")
        assert forbidden.status == 403


@pytest.mark.asyncio
async def test_guard_requires_principal() -> None:
    provider = DependencyProvider()
    engine = CedarEngine([])
    provider.provide(CedarEngine, lambda: engine)
    app = ArtemisApp(
        AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)),
        dependency_provider=provider,
    )

    guard = RouteGuard(action="items:read", resource_type="item")

    @app.get("/auth/required", authorize=[guard])
    async def secured() -> dict[str, str]:
        return {"status": "ok"}

    async with TestClient(app) as client:
        response = await client.get("/auth/required", tenant="acme")
        assert response.status == 403
        payload = json_decode(response.body)
        assert payload["error"]["detail"]["detail"] == "authentication_required"


@pytest.mark.asyncio
async def test_guard_rejects_principal_type_mismatch() -> None:
    provider = DependencyProvider()
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("AdminUser", "admin"),
        actions=("items:read",),
        resource=CedarReference("item", "*"),
    )
    engine = CedarEngine([policy])
    provider.provide(CedarEngine, lambda: engine)
    app = ArtemisApp(
        AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)),
        dependency_provider=provider,
    )

    async def identity(request: Request, handler: Callable[[Request], Awaitable[Response]]) -> Response:
        request.with_principal(CedarEntity(type="User", id="user"))
        return await handler(request)

    app.add_middleware(identity)

    guard = RouteGuard(action="items:read", resource_type="item", principal_type="AdminUser")

    @app.get("/admin-only", authorize=guard)
    async def admin_only() -> dict[str, str]:
        return {"status": "ok"}

    async with TestClient(app) as client:
        response = await client.get("/admin-only", tenant="acme")
        assert response.status == 403
        payload = json_decode(response.body)
        assert payload["error"]["detail"]["detail"] == "principal_not_allowed"


@pytest.mark.asyncio
async def test_app_guard_sets_global_guards() -> None:
    provider = DependencyProvider()
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "allowed"),
        actions=("inventory:view",),
        resource=CedarReference("inventory", "*"),
    )
    engine = CedarEngine([policy])
    provider.provide(CedarEngine, lambda: engine)
    app = ArtemisApp(
        AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)),
        dependency_provider=provider,
    )

    async def identity(request: Request, handler: Callable[[Request], Awaitable[Response]]) -> Response:
        user = request.header("x-user", "denied") or "denied"
        request.with_principal(CedarEntity(type="User", id=user))
        return await handler(request)

    app.add_middleware(identity)

    app.guard(RouteGuard(action="inventory:view", resource_type="inventory"))

    @app.get("/inventory")
    async def inventory() -> dict[str, str]:
        return {"items": []}

    async with TestClient(app) as client:
        forbidden = await client.get("/inventory", tenant="acme")
        assert forbidden.status == 403
        allowed = await client.get("/inventory", tenant="acme", headers={"x-user": "allowed"})
        assert allowed.status == 200


@pytest.mark.asyncio
async def test_none_response_coerces_to_204(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        response = await client.get("/noop", tenant="acme")
    assert response.status == 204
    assert response.body == b""


@pytest.mark.asyncio
async def test_unannotated_path_param(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        response = await client.get("/echo/sample", tenant="acme")
    payload = json_decode(response.body)
    assert payload == {"value": "sample"}


@pytest.mark.asyncio
async def test_execute_route_struct_injection(app: ArtemisApp) -> None:
    match = app.router.find("POST", "/items")
    tenant = app.tenant_resolver.context_for("acme")
    request = Request(
        method="POST",
        path="/items",
        tenant=tenant,
        headers={"content-type": "application/json"},
        body=json_encode({"name": "Gadget"}),
    )
    scope = app.dependencies.scope(request)
    response = await app._execute_route(match.route, request, scope)
    payload = json_decode(response.body)
    assert payload["item"]["name"] == "Gadget"


@pytest.mark.asyncio
async def test_double_struct_reuse(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        response = await client.post("/double", tenant="acme", json={"name": "Mirror"})
    payload = json_decode(response.body)
    assert payload == {"first": "Mirror", "second": "Mirror"}


@pytest.mark.asyncio
async def test_execute_route_missing_dependency_error() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.get("/needs")
    def needs(missing: MissingDependency):  # type: ignore[no-untyped-def]
        return "missing"

    tenant = app.tenant_resolver.context_for("acme")
    request = Request(method="GET", path="/needs", tenant=tenant)
    scope = app.dependencies.scope(request)
    match = app.router.find("GET", "/needs")
    with pytest.raises(HTTPError):
        await app._execute_route(match.route, request, scope)


@pytest.mark.asyncio
async def test_execute_route_coroutine_direct() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.get("/async-call")
    def async_call():  # type: ignore[no-untyped-def]
        async def inner() -> str:
            return "async"

        return inner()

    tenant = app.tenant_resolver.context_for("acme")
    request = Request(method="GET", path="/async-call", tenant=tenant)
    scope = app.dependencies.scope(request)
    match = app.router.find("GET", "/async-call")
    response = await app._execute_route(match.route, request, scope)
    assert response.body == b"async"
