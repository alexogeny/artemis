from __future__ import annotations

from typing import Mapping, cast

import pytest

from artemis.application import ArtemisApp
from artemis.config import AppConfig
from artemis.requests import Request
from artemis.responses import Response
from artemis.serialization import json_encode


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

    messages: list[Mapping[str, object]] = []

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    scope = {"type": "websocket", "headers": []}
    await app(scope, receive, send)
    assert messages == [{"type": "websocket.close", "code": 4400}]

    scope = {"type": "lifespan"}
    with pytest.raises(RuntimeError):
        await app(scope, receive, send)


@pytest.mark.asyncio
async def test_asgi_collects_body_chunks() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.post("/upload")
    async def upload(request: Request) -> Response:
        payload = await request.body()
        assert payload is await request.body()
        return Response(body=payload)

    messages: list[dict[str, object]] = []
    chunks = [
        {"type": "http.request", "body": b"", "more_body": True},
        {"type": "http.request", "body": b"chunk-1", "more_body": True},
        {"type": "http.request", "body": b"", "more_body": True},
        {"type": "http.request", "body": b"chunk-2", "more_body": False},
    ]

    async def receive() -> Mapping[str, object]:
        if chunks:
            return chunks.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    await app(
        {
            "type": "http",
            "method": "POST",
            "path": "/upload",
            "query_string": b"",
            "headers": [(b"host", b"acme.demo.example.com")],
        },
        receive,
        send,
    )
    await app.shutdown()

    assert messages[-1]["body"] == b"chunk-1chunk-2"


@pytest.mark.asyncio
async def test_asgi_large_post_body_reuse() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.post("/bulk")
    async def bulk(request: Request) -> Response:
        first = await request.body()
        second = await request.body()
        assert first is second
        decoded_body = first.decode()
        text = await request.text()
        assert text == decoded_body
        parsed = await request.json()
        again = await request.json()
        assert parsed is again
        return Response(body=str(len(first)).encode())

    payload_obj = {"records": ["x" * 512 for _ in range(512)]}
    payload = json_encode(payload_obj)
    chunk_size = 65536
    chunks: list[dict[str, object]] = []
    for index in range(0, len(payload), chunk_size):
        chunk = payload[index : index + chunk_size]
        chunks.append(
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index + chunk_size < len(payload),
            }
        )
    chunks.insert(0, {"type": "http.request", "body": b"", "more_body": True})

    messages: list[dict[str, object]] = []

    async def receive() -> Mapping[str, object]:
        if chunks:
            return chunks.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    await app(
        {
            "type": "http",
            "method": "POST",
            "path": "/bulk",
            "query_string": b"",
            "headers": [
                (b"host", b"acme.demo.example.com"),
                (b"content-type", b"application/json"),
            ],
        },
        receive,
        send,
    )
    await app.shutdown()

    assert not chunks
    assert messages[0]["status"] == 200
    body = cast(bytes, messages[-1]["body"])
    assert int(body.decode()) == len(payload)


@pytest.mark.asyncio
async def test_asgi_body_loader_handles_disconnect_and_cached_reads() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.post("/manual")
    async def manual(request: Request) -> Response:
        loader = request._body_loader
        assert loader is not None
        first = await loader()
        second = await loader()
        assert first is second
        body = await request.body()
        assert body is first
        return Response(body=body)

    incoming: list[dict[str, object]] = [
        {"type": "lifespan.startup"},
        {"type": "http.request", "body": b"chunk-a", "more_body": True},
        {"type": "http.request", "body": b"chunk-b", "more_body": True},
        {"type": "http.disconnect"},
    ]
    messages: list[dict[str, object]] = []

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    await app(
        {
            "type": "http",
            "method": "POST",
            "path": "/manual",
            "query_string": b"",
            "headers": [(b"host", b"acme.demo.example.com")],
        },
        receive,
        send,
    )
    await app.shutdown()

    assert messages[0]["status"] == 200
    assert messages[-1]["body"] == b"chunk-achunk-b"
    assert not incoming
