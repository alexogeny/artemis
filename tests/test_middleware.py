from __future__ import annotations

import pytest

from artemis.application import ArtemisApp
from artemis.config import AppConfig
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
