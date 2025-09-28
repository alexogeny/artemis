from __future__ import annotations

from typing import Any, AsyncIterator, Awaitable, Callable, Mapping

import msgspec
import pytest
import pytest_asyncio

from artemis.application import Artemis, ArtemisApp
from artemis.audit import AuditTrail, current_actor
from artemis.config import AppConfig
from artemis.database import Database, DatabaseConfig, PoolConfig
from artemis.dependency import DependencyProvider
from artemis.exceptions import HTTPError
from artemis.http import Status
from artemis.orm import ORM
from artemis.rbac import CedarEffect, CedarEngine, CedarEntity, CedarPolicy, CedarReference
from artemis.requests import Request
from artemis.responses import (
    DEFAULT_SECURITY_HEADERS,
    JSONResponse,
    Response,
    security_headers_middleware,
)
from artemis.routing import RouteGuard, get
from artemis.serialization import json_decode, json_encode
from artemis.tenancy import TenantContext
from artemis.testing import TestClient
from artemis.websockets import WebSocket
from tests.support import FakeConnection, FakePool


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
        assert payload == {"error": {"status": 403, "reason": "Forbidden", "detail": "admin scope required"}}


@pytest.mark.asyncio
async def test_query_parsing(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        response = await client.get("/search", tenant="acme", query={"limit": 5, "offset": 2})
        assert json_decode(response.body) == {"limit": 5, "offset": 2}


@pytest.mark.asyncio
async def test_security_headers_present(app: ArtemisApp) -> None:
    async with TestClient(app) as client:
        response = await client.get("/noop", tenant="acme")
        headers = dict(response.headers)
        for name, value in DEFAULT_SECURITY_HEADERS:
            assert headers.get(name) == value


def test_security_middleware_ordering() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    async def custom(request: Request, handler):
        return await handler(request)

    app.add_middleware(custom)
    assert app._middlewares[-1] is security_headers_middleware
    assert app._middlewares[-2] is custom

    app.add_middleware(security_headers_middleware)
    assert app._middlewares.count(security_headers_middleware) == 1

    app._middlewares.pop()
    app.add_middleware(custom)
    assert app._middlewares[-1] is custom


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

    async def identity_middleware(request: Request, handler: Callable[[Request], Awaitable[Response]]) -> Response:
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
        assert payload["error"]["reason"] == "Forbidden"
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
        assert payload["error"]["reason"] == "Forbidden"
        assert payload["error"]["detail"]["detail"] == "principal_not_allowed"


@pytest.mark.asyncio
async def test_dispatch_handles_status_enum_exception(app: ArtemisApp) -> None:
    class StatusError(Exception):
        def __init__(self, status: Status | int) -> None:
            super().__init__("boom")
            self.status = status

    @app.get("/status-error")
    async def raises_status_error() -> None:
        raise StatusError(Status.BAD_REQUEST)

    @app.get("/status-int-error")
    async def raises_int_error() -> None:
        raise StatusError(400)

    async with TestClient(app) as client:
        with pytest.raises(StatusError):
            await client.get("/status-error", tenant="acme")
        with pytest.raises(StatusError):
            await client.get("/status-int-error", tenant="acme")


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
async def test_asgi_sanitizes_non_utf8_header_bytes() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.get("/inspect")
    async def inspect(request: Request) -> Response:
        return JSONResponse({"header": request.header("x-weird")})

    messages: list[dict[str, Any]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "GET",
                "path": "/inspect",
                "query_string": b"",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"https://acme.demo.example.com"),
                    (b"x-weird", b"\xff\xfe"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["status"] == 200
    payload = json_decode(messages[-1]["body"])
    assert payload == {"header": "ÿþ"}


@pytest.mark.asyncio
async def test_asgi_rejects_scope_with_invalid_host_bytes() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.get("/noop")
    async def noop() -> None:
        return None

    messages: list[dict[str, Any]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "GET",
                "path": "/noop",
                "query_string": b"",
                "headers": [(b"host", b"\xff\xfe")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["status"] == 400
    payload = json_decode(messages[-1]["body"])
    assert payload["error"]["detail"]["detail"] == "invalid_host_header"


@pytest.mark.asyncio
async def test_asgi_rejects_scope_without_host_header() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.get("/noop")
    async def noop() -> None:
        return None

    messages: list[dict[str, Any]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "GET",
                "path": "/noop",
                "query_string": b"",
                "headers": [],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["status"] == 400
    payload = json_decode(messages[-1]["body"])
    assert payload["error"]["detail"]["detail"] == "missing_host_header"


@pytest.mark.asyncio
async def test_asgi_rejects_scope_with_unencodable_headers() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.get("/noop")
    async def noop() -> None:
        return None

    messages: list[dict[str, Any]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "GET",
                "path": "/noop",
                "query_string": b"",
                "headers": [
                    (b"", b"ignored"),
                    ("x-text", "value"),
                    (object(), b"value"),
                    (b"host", b"acme.demo.example.com"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["status"] == 400
    payload = json_decode(messages[-1]["body"])
    assert payload["error"]["detail"]["detail"] == "invalid_header_encoding"


@pytest.mark.asyncio
async def test_asgi_decodes_non_utf8_query_string() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.get("/inspect")
    async def inspect(request: Request) -> Response:
        params = {key: list(values) for key, values in request.query_params.items()}
        return JSONResponse({"params": params})

    messages: list[dict[str, Any]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "GET",
                "path": "/inspect",
                "query_string": b"\xff=\xfe",
                "headers": [(b"host", b"acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["status"] == 200
    payload = json_decode(messages[-1]["body"])
    assert payload == {"params": {"ÿ": ["þ"]}}


@pytest.mark.asyncio
async def test_http_request_rejects_excessive_content_length() -> None:
    app = ArtemisApp(
        AppConfig(
            site="demo",
            domain="example.com",
            allowed_tenants=("acme",),
            max_request_body_bytes=4,
        )
    )

    @app.post("/ingest")
    async def ingest(request: Request) -> Response:  # pragma: no cover - should not execute
        await request.body()
        return JSONResponse({"ok": True})

    messages: list[dict[str, Any]] = []
    receive_calls = 0

    async def receive() -> Mapping[str, object]:
        nonlocal receive_calls
        receive_calls += 1
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "POST",
                "path": "/ingest",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"content-length", b"10"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert receive_calls == 0
    assert messages[0]["status"] == int(Status.PAYLOAD_TOO_LARGE)
    payload = json_decode(messages[-1]["body"])
    assert payload["error"]["detail"]["detail"] == "request_body_too_large"


@pytest.mark.asyncio
async def test_http_request_streaming_enforces_body_limit() -> None:
    app = ArtemisApp(
        AppConfig(
            site="demo",
            domain="example.com",
            allowed_tenants=("acme",),
            max_request_body_bytes=6,
        )
    )

    @app.post("/ingest")
    async def ingest(request: Request) -> Response:
        await request.body()
        return JSONResponse({"ok": True})

    messages: list[dict[str, Any]] = []
    incoming: list[Mapping[str, object]] = [
        {"type": "http.request", "body": b"abcd", "more_body": True},
        {"type": "http.request", "body": b"efgh", "more_body": False},
    ]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "POST",
                "path": "/ingest",
                "query_string": "skip=1",
                "headers": [(b"host", b"acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["status"] == int(Status.PAYLOAD_TOO_LARGE)
    payload = json_decode(messages[-1]["body"])
    assert payload["error"]["detail"]["detail"] == "request_body_too_large"


@pytest.mark.asyncio
@pytest.mark.parametrize("content_length", [b"oops", b"-1"])
async def test_http_request_with_invalid_content_length_header(content_length: bytes) -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.post("/ingest")
    async def ingest(request: Request) -> Response:  # pragma: no cover - should not execute
        await request.body()
        return JSONResponse({"ok": True})

    messages: list[dict[str, Any]] = []
    receive_calls = 0

    async def receive() -> Mapping[str, object]:
        nonlocal receive_calls
        receive_calls += 1
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "POST",
                "path": "/ingest",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"content-length", content_length),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert receive_calls == 0
    assert messages[0]["status"] == int(Status.BAD_REQUEST)
    payload = json_decode(messages[-1]["body"])
    assert payload["error"]["detail"]["detail"] == "invalid_content_length"


@pytest.mark.asyncio
async def test_http_request_allows_content_length_within_limit() -> None:
    app = ArtemisApp(
        AppConfig(
            site="demo",
            domain="example.com",
            allowed_tenants=("acme",),
            max_request_body_bytes=8,
        )
    )

    @app.post("/ingest")
    async def ingest(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"size": len(body)})

    messages: list[dict[str, Any]] = []
    incoming: list[Mapping[str, object]] = [
        {"type": "http.request", "body": b"data", "more_body": False},
    ]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "POST",
                "path": "/ingest",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"content-length", b"4"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["status"] == 200
    payload = json_decode(messages[-1]["body"])
    assert payload == {"size": 4}


@pytest.mark.asyncio
async def test_http_request_without_body_limit_allows_large_payload() -> None:
    app = ArtemisApp(
        AppConfig(
            site="demo",
            domain="example.com",
            allowed_tenants=("acme",),
            max_request_body_bytes=None,
        )
    )

    @app.post("/ingest")
    async def ingest(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"size": len(body)})

    messages: list[dict[str, Any]] = []
    incoming: list[Mapping[str, object]] = [
        {
            "type": "http.request",
            "body": b"abcdefghij",
            "more_body": False,
        },
    ]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "http",
                "method": "POST",
                "path": "/ingest",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"content-length", b"10"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["status"] == 200
    payload = json_decode(messages[-1]["body"])
    assert payload == {"size": 10}


@pytest.mark.asyncio
async def test_websocket_scope_sanitizes_headers() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.websocket("/ws")
    async def websocket_endpoint(socket: WebSocket) -> None:
        assert socket.request.header("x-weird") == "ÿþ"
        await socket.accept()
        await socket.close()

    messages: list[dict[str, Any]] = []
    incoming: list[Mapping[str, object]] = [{"type": "websocket.connect"}]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "query_string": b"",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"https://acme.demo.example.com"),
                    (b"x-weird", b"\xff\xfe"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[0]["type"] == "websocket.accept"
    assert messages[-1]["type"] == "websocket.close"


@pytest.mark.asyncio
async def test_websocket_scope_without_host_header_closes_with_protocol_error() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.websocket("/noop")
    async def noop(socket: WebSocket) -> None:  # pragma: no cover - should not execute
        await socket.accept()

    messages: list[dict[str, Any]] = []
    incoming: list[Mapping[str, object]] = [{"type": "websocket.connect"}]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/noop",
                "query_string": b"",
                "headers": [],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4400}]


@pytest.mark.asyncio
async def test_websocket_scope_with_unencodable_headers_closes_with_protocol_error() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",)))

    @app.websocket("/noop")
    async def noop(socket: WebSocket) -> None:  # pragma: no cover - should not execute
        await socket.accept()

    messages: list[dict[str, Any]] = []
    incoming: list[Mapping[str, object]] = [{"type": "websocket.connect"}]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/noop",
                "query_string": b"",
                "headers": [
                    (b"", b"ignored"),
                    ("x-text", "value"),
                    (object(), b"value"),
                    (b"host", b"acme.demo.example.com"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4400}]


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


def _app_with_database() -> tuple[ArtemisApp, Database, ORM]:
    connection = FakeConnection()
    pool = FakePool(connection)
    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://demo"), tenant_schema_template="tenant_{tenant}")
    database = Database(config, pool=pool)
    orm = ORM(database)
    app = ArtemisApp(AppConfig(database=config, allowed_tenants=("acme",)), database=database, orm=orm)
    return app, database, orm


def test_application_reuses_existing_audit_trail() -> None:
    _app, database, orm = _app_with_database()
    audit = AuditTrail(database, registry=orm.registry)
    orm.attach_audit_trail(audit)

    reused = ArtemisApp(AppConfig(database=database.config, allowed_tenants=("acme",)), database=database, orm=orm)
    assert reused.audit_trail is audit


def test_application_initializes_audit_trail_when_missing() -> None:
    app, _, orm = _app_with_database()
    assert app.audit_trail is not None
    assert getattr(orm, "_audit_trail") is app.audit_trail


def test_application_without_database_has_no_audit_trail() -> None:
    app = ArtemisApp(AppConfig())
    assert app.audit_trail is None


def test_application_handles_missing_orm(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    config = DatabaseConfig(pool=PoolConfig(dsn="postgres://demo"), tenant_schema_template="tenant_{tenant}")
    database = Database(config, pool=pool)

    monkeypatch.setattr("artemis.application.ORM", lambda _: None)
    app = ArtemisApp(AppConfig(database=config, allowed_tenants=("acme",)), database=database)
    assert app.orm is None
    assert app.audit_trail is not None


@pytest.mark.asyncio
async def test_dispatch_binds_audit_actor_from_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    app, _, _ = _app_with_database()

    class AutoPrincipalRequest(Request):
        def __init__(self, *args: Any, headers: Mapping[str, str] | None = None, **kwargs: Any) -> None:
            super().__init__(*args, headers=headers, **kwargs)
            header_user = (headers or {}).get("x-user")
            if header_user:
                self.with_principal(CedarEntity(type="User", id=header_user))

    monkeypatch.setattr("artemis.application.Request", AutoPrincipalRequest)

    @app.get("/actor")
    async def actor_endpoint() -> dict[str, str | None]:
        actor = current_actor()
        return {"actor": actor.id if actor else None}

    anonymous = await app.dispatch("GET", "/actor", host="acme.demo.example.com")
    assert json_decode(anonymous.body) == {"actor": None}

    admin = await app.dispatch(
        "GET",
        "/actor",
        host="acme.demo.example.com",
        headers={"x-user": "admin"},
    )
    assert json_decode(admin.body) == {"actor": "admin"}
