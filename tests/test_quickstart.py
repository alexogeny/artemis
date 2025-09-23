from __future__ import annotations

import json

import pytest

from artemis import AppConfig, ArtemisApp, TestClient
from artemis.quickstart import attach_quickstart


@pytest.mark.asyncio
async def test_attach_quickstart_routes_dev_environment() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))
    attach_quickstart(app)

    async with TestClient(app) as client:
        for tenant in ("acme", "beta", app.config.admin_subdomain):
            ping = await client.get("/__artemis/ping", tenant=tenant)
            assert ping.status == 200
            assert ping.body.decode() == "pong"

            openapi = await client.get("/__artemis/openapi.json", tenant=tenant)
            assert openapi.status == 200
            spec = json.loads(openapi.body.decode())
            assert "/__artemis/ping" in spec["paths"]

            client_ts = await client.get("/__artemis/client.ts", tenant=tenant)
            assert client_ts.status == 200
            assert ("content-type", "application/typescript") in client_ts.headers
            assert "export class ArtemisClient" in client_ts.body.decode()


def test_attach_quickstart_rejects_production() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    with pytest.raises(RuntimeError):
        attach_quickstart(app, environment="production")


@pytest.mark.asyncio
async def test_attach_quickstart_with_root_base_path() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))
    attach_quickstart(app, base_path="")

    async with TestClient(app) as client:
        response = await client.get("/ping", tenant="acme")
        assert response.status == 200
        assert response.body.decode() == "pong"
