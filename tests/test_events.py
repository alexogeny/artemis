from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping

import pytest

from mere.application import MereApp, _send_response_body
from mere.config import AppConfig
from mere.events import EventStream, ServerSentEvent
from mere.events import _ensure_awaitable as _ensure_event_awaitable
from mere.events import _log_task_error as _log_event_task_error
from mere.execution import ExecutionMode
from mere.requests import Request
from mere.responses import Response


@pytest.mark.asyncio
async def test_event_stream_emits_across_tenants() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.sse("/events/{name}")
    async def events(name: str, stream: EventStream, request: Request) -> EventStream:
        async def producer() -> None:
            await asyncio.sleep(0)
            await stream.send(
                ServerSentEvent(
                    data={"tenant": request.tenant.tenant, "name": name},
                    event="update",
                    json=True,
                )
            )
            await stream.close()

        stream.fork(producer)
        return stream

    await app.startup()
    hosts: Mapping[str, str] = {
        "acme": "acme.demo.example.com",
        "beta": "beta.demo.example.com",
        "admin": "admin.demo.example.com",
    }
    try:
        for tenant, host in hosts.items():
            response = await app.dispatch("GET", f"/events/{tenant}", host=host)
            assert response.stream is not None
            chunks: list[bytes] = []
            async for chunk in response.stream:
                chunks.append(chunk)
            payload = b"".join(chunks).decode()
            assert "event: update" in payload
            data_lines = [line[len("data: ") :] for line in payload.splitlines() if line.startswith("data: ")]
            assert data_lines
            event_payload = json.loads(data_lines[-1])
            assert event_payload["name"] == tenant
            assert event_payload["tenant"] == tenant
    finally:
        await app.shutdown()


@pytest.mark.asyncio
async def test_event_stream_background_executor() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.get("/batch")
    async def batch(stream: EventStream) -> EventStream:
        def compute() -> list[dict[str, str]]:
            return [{"message": "from-thread"}]

        stream.fork(compute, mode=ExecutionMode.THREAD)
        await stream.join_background()
        await stream.close()
        return stream

    await app.startup()
    try:
        response = await app.dispatch("GET", "/batch", host="acme.demo.example.com")
        assert response.stream is not None
        chunks: list[bytes] = []
        async for chunk in response.stream:
            chunks.append(chunk)
        payload = b"".join(chunks).decode()
        data_lines = [line[len("data: ") :] for line in payload.splitlines() if line.startswith("data: ")]
        assert data_lines
        event_payload = json.loads(data_lines[-1])
        assert event_payload == {"message": "from-thread"}
    finally:
        await app.shutdown()


@pytest.mark.asyncio
async def test_event_stream_auto_return_on_none() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.get("/auto")
    async def auto(stream: EventStream) -> None:
        await stream.send("auto")
        await stream.close()

    await app.startup()
    try:
        response = await app.dispatch("GET", "/auto", host="acme.demo.example.com")
    finally:
        await app.shutdown()

    assert response.stream is not None
    chunks = [chunk async for chunk in response.stream]
    payload = b"".join(chunks).decode()
    assert "data: auto" in payload


@pytest.mark.asyncio
async def test_event_stream_primitives() -> None:
    stream = EventStream()
    assert not stream.closed

    async def async_producer() -> None:
        await asyncio.sleep(0)
        await stream.send("async")

    stream.fork(async_producer)

    def threaded_payload() -> list[object]:
        return [
            "threaded",
            b"binary",
            {"value": 42},
            ServerSentEvent(data="event", event="note"),
            7,
        ]

    with pytest.raises(TypeError):
        stream.fork(lambda: 1)
    stream.fork(threaded_payload, mode=ExecutionMode.THREAD)
    stream.fork(lambda: None, mode=ExecutionMode.THREAD)
    await stream.send(ServerSentEvent(data={"gamma": True}, event_id="evt", retry=5, json=True))
    await stream.send("alpha")
    await stream.send(
        ServerSentEvent(data="overridden", event="source", event_id="orig", retry=1),
        event="manual",
        event_id="explicit",
        retry=9,
    )
    await stream.send("")
    await stream.send("line\n")

    response = stream.to_response(headers=(("x-test", "yes"),))
    assert response.stream is not None
    assert any(name == "content-type" and value == "text/event-stream" for name, value in response.headers)

    await stream.join_background()
    await stream.close()
    await stream.close()

    chunks: list[bytes] = []
    async for chunk in response.stream:
        chunks.append(chunk)
    payload = b"".join(chunks).decode()
    assert "data: async" in payload
    assert "data: threaded" in payload
    assert "data: binary" in payload
    assert '"value":42' in payload
    assert "event: note" in payload
    assert "data: 7" in payload
    assert "retry: 5" in payload
    assert "event: manual" in payload
    assert "id: explicit" in payload
    assert "retry: 9" in payload
    assert stream.closed

    with pytest.raises(RuntimeError):
        await stream.send("after")


@pytest.mark.asyncio
async def test_event_stream_background_cancellation() -> None:
    stream = EventStream()

    stalled = asyncio.Event()

    async def wait_forever() -> None:
        await stalled.wait()

    task = stream.fork(wait_forever)
    response = stream.to_response()
    await stream.close()

    collected: list[bytes] = []
    assert response.stream is not None
    async for chunk in response.stream:
        collected.append(chunk)
    assert collected == []
    assert stream.closed
    assert task.cancelled()
    await stream.join_background()


@pytest.mark.asyncio
async def test_event_stream_multiple_stream_parameters_error() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.get("/multi")
    async def multi(first: EventStream, second: EventStream) -> None:
        return None

    await app.startup()
    try:
        with pytest.raises(RuntimeError):
            await app.dispatch("GET", "/multi", host="acme.demo.example.com")
    finally:
        await app.shutdown()


@pytest.mark.asyncio
async def test_event_stream_empty_stream_asgi() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.get("/empty")
    async def empty(stream: EventStream) -> EventStream:
        await stream.close()
        return stream

    messages: list[dict[str, object]] = []

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
                "path": "/empty",
                "query_string": b"",
                "headers": [(b"host", b"acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages[1]["more_body"] is False
    assert messages[1]["body"] == b""


@pytest.mark.asyncio
async def test_send_response_body_handles_async_iterable() -> None:
    class Wrapper:
        def __aiter__(self):
            async def generator():
                yield b"chunk-one"
                yield b"chunk-two"

            return generator()

    response = Response(stream=Wrapper())
    messages: list[dict[str, object]] = []

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await _send_response_body(response, send)
    assert messages[0]["more_body"] is True
    assert messages[0]["body"] == b"chunk-one"
    assert messages[1]["more_body"] is True
    assert messages[1]["body"] == b"chunk-two"
    assert messages[2]["more_body"] is False
    assert messages[2]["body"] == b""


@pytest.mark.asyncio
async def test_event_stream_log_task_error() -> None:
    async def boom() -> None:
        raise RuntimeError("boom")

    task = asyncio.create_task(boom())
    with pytest.raises(RuntimeError):
        await task
    _log_event_task_error(task)


def test_event_stream_ensure_awaitable_type_error() -> None:
    with pytest.raises(TypeError):
        _ensure_event_awaitable("nope")
