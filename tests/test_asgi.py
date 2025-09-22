from __future__ import annotations

from typing import Mapping

import pytest

from artemis.application import ArtemisApp
from artemis.config import AppConfig


@pytest.mark.asyncio
async def test_asgi_interface_handles_request() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.get("/ping")
    async def ping() -> str:
        return "pong"

    messages: list[dict[str, object]] = []
    incoming = [
        {"type": "lifespan.startup"},
        {"type": "http.request", "body": b"", "more_body": False},
    ]

    async def receive() -> Mapping[str, object]:
        return incoming.pop(0) if incoming else {"type": "http.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    await app(
        {
            "type": "http",
            "method": "GET",
            "path": "/ping",
            "query_string": b"",
            "headers": [(b"host", b"acme.demo.example.com")],
        },
        receive,
        send,
    )
    await app.shutdown()
    assert messages[0]["status"] == 200
    assert messages[1]["body"] == b"pong"


@pytest.mark.asyncio
async def test_asgi_requires_host_header() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.get("/ping")
    async def ping() -> str:
        return "pong"

    async def receive() -> Mapping[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        raise AssertionError("send should not be called")

    scope = {"type": "http", "method": "GET", "path": "/ping", "query_string": b"", "headers": []}
    with pytest.raises(RuntimeError):
        await app(scope, receive, send)


@pytest.mark.asyncio
async def test_asgi_rejects_non_http_scope() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    async def receive() -> Mapping[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Mapping[str, object]) -> None:
        raise AssertionError("send should not be called")

    scope = {"type": "websocket", "headers": []}
    with pytest.raises(RuntimeError):
        await app(scope, receive, send)
