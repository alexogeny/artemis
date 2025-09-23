from __future__ import annotations

import pytest

from artemis.application import ArtemisApp
from artemis.config import AppConfig
from artemis.middleware import apply_middleware
from artemis.requests import Request
from artemis.responses import Response
from artemis.tenancy import TenantContext, TenantScope
from artemis.testing import TestClient


@pytest.mark.asyncio
async def test_middleware_executes_in_order() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    events: list[str] = []

    async def recorder(request, handler):
        events.append(f"before:{request.tenant.tenant}")
        response = await handler(request)
        events.append(f"after:{request.tenant.tenant}")
        return response

    app.add_middleware(recorder)

    @app.get("/ping")
    async def ping() -> str:
        return "pong"

    async with TestClient(app) as client:
        response_acme = await client.get("/ping", tenant="acme")
        response_beta = await client.get("/ping", tenant="beta")
    assert response_acme.body == b"pong"
    assert response_beta.body == b"pong"
    assert events == ["before:acme", "after:acme", "before:beta", "after:beta"]


class _StubObservability:
    def __init__(self) -> None:
        self.enabled = True
        self.started: list[tuple[object, object, object]] = []
        self.succeeded: list[object] = []
        self.errored: list[tuple[object, BaseException]] = []

    def on_middleware_start(self, middleware, request, request_context):
        context = object()
        self.started.append((middleware, request_context, context))
        return context

    def on_middleware_success(self, context):
        self.succeeded.append(context)

    def on_middleware_error(self, context, exc):
        self.errored.append((context, exc))


@pytest.mark.asyncio
async def test_apply_middleware_reports_success_to_observability() -> None:
    observability = _StubObservability()

    async def middleware(request: Request, handler):
        return await handler(request)

    async def endpoint(request: Request) -> Response:
        return Response(status=204)

    handler = apply_middleware([middleware], endpoint, observability=observability, request_context="ctx")
    request = Request(
        method="GET",
        path="/", 
        headers={},
        tenant=TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
        path_params={},
        query_string="",
        body=b"",
    )
    response = await handler(request)
    assert response.status == 204
    assert observability.started[0][1] == "ctx"
    context = observability.started[0][2]
    assert observability.succeeded == [context]
    assert not observability.errored


@pytest.mark.asyncio
async def test_apply_middleware_reports_error_to_observability() -> None:
    observability = _StubObservability()

    async def failing(request: Request, handler):
        raise RuntimeError("middleware failure")

    async def endpoint(request: Request) -> Response:
        return Response()

    handler = apply_middleware([failing], endpoint, observability=observability)
    request = Request(
        method="GET",
        path="/", 
        headers={},
        tenant=TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
        path_params={},
        query_string="",
        body=b"",
    )
    with pytest.raises(RuntimeError):
        await handler(request)
    assert not observability.succeeded
    assert isinstance(observability.errored[0][1], RuntimeError)


@pytest.mark.asyncio
async def test_apply_middleware_without_observability() -> None:
    calls: list[str] = []

    async def middleware(request: Request, handler):
        calls.append("middleware")
        return await handler(request)

    async def endpoint(request: Request) -> Response:
        calls.append("endpoint")
        return Response(status=200)

    handler = apply_middleware([middleware], endpoint)
    request = Request(
        method="GET",
        path="/",
        headers={},
        tenant=TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT),
        path_params={},
        query_string="",
        body=b"",
    )
    response = await handler(request)
    assert response.status == 200
    assert calls == ["middleware", "endpoint"]
