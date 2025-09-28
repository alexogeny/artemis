import pytest

from mere.adapters.fastapi import mount_fastapi
from mere.application import MereApp
from mere.config import AppConfig
from mere.serialization import json_decode, json_encode

pytestmark = pytest.mark.asyncio


async def test_mount_fastapi_routes_dispatch() -> None:
    from fastapi import FastAPI

    legacy = FastAPI()

    @legacy.get("/hello/{name}")
    async def hello(name: str) -> dict[str, str]:
        return {"message": f"hello {name}"}

    state: dict[str, bool] = {"started": False, "stopped": False}

    async def _startup() -> None:
        state["started"] = True

    async def _shutdown() -> None:
        state["stopped"] = True

    legacy.router.on_startup.append(_startup)
    legacy.router.on_shutdown.append(_shutdown)

    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    mount_fastapi(app, legacy, prefix="/legacy")

    await app.startup()
    response = await app.dispatch("GET", "/legacy/hello/world", host="acme.demo.example.com")
    payload = json_decode(response.body)
    await app.shutdown()

    assert response.status == 200
    assert payload == {"message": "hello world"}
    assert state == {"started": True, "stopped": True}


async def test_mount_fastapi_passes_body_and_headers() -> None:
    from fastapi import FastAPI
    from fastapi import Request as FastAPIRequest

    legacy = FastAPI()

    @legacy.post("/echo")
    async def echo(request: FastAPIRequest) -> dict[str, object]:
        content_type = request.headers.get("content-type")
        data = await request.json()
        return {"content_type": content_type, "data": data, "query": dict(request.query_params)}

    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    mount_fastapi(app, legacy, prefix="/legacy")

    await app.startup()
    payload = json_encode({"value": 1})
    response = await app.dispatch(
        "POST",
        "/legacy/echo?source=migration",
        host="acme.demo.example.com",
        headers={"content-type": "application/json"},
        body=payload,
    )
    await app.shutdown()

    assert response.status == 200
    decoded = json_decode(response.body)
    assert decoded == {
        "content_type": "application/json",
        "data": {"value": 1},
        "query": {"source": "migration"},
    }
