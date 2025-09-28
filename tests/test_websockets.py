from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import cast

import pytest

from mere.application import MereApp, _status_to_websocket_close
from mere.config import AppConfig
from mere.exceptions import HTTPError
from mere.execution import ExecutionMode, TaskExecutor
from mere.http import Status
from mere.requests import Request
from mere.routing import RouteGuard
from mere.tenancy import TenantContext, TenantScope
from mere.websockets import WebSocket, WebSocketDisconnect
from mere.websockets import _log_task_error as _log_ws_task_error


class RouteHelper:
    pass


@pytest.mark.asyncio
async def test_websocket_echo_and_background() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws/{channel}")
    async def ws(channel: str, socket: WebSocket) -> None:
        await socket.accept()
        message = await socket.receive_text()
        await socket.send_text(f"{channel}:{message}")

        async def background() -> None:
            await asyncio.sleep(0)
            await socket.send_json({"tenant": socket.request.tenant.tenant})

        socket.fork(background)
        await socket.join_background()
        await socket.close()

    messages: list[Mapping[str, object]] = []
    incoming = [
        {"type": "websocket.connect"},
        {"type": "websocket.receive", "text": "ping"},
    ]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws/chat",
                "query_string": b"",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
                "subprotocols": [],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert any(msg.get("type") == "websocket.accept" for msg in messages)
    text_payloads = [msg.get("text") for msg in messages if msg.get("type") == "websocket.send"]
    assert "chat:ping" in text_payloads
    assert any("tenant" in str(payload) for payload in text_payloads)
    assert any(msg.get("type") == "websocket.close" for msg in messages)


@pytest.mark.asyncio
async def test_websocket_executor_background() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/worker")
    async def worker(socket: WebSocket) -> None:
        await socket.accept()

        def produce() -> list[str]:
            return ["background"]

        socket.fork(produce, mode=ExecutionMode.THREAD)
        await socket.join_background()
        await socket.close()

    messages: list[Mapping[str, object]] = []
    incoming = [{"type": "websocket.connect"}]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/worker",
                "query_string": b"",
                "headers": [(b"host", b"beta.demo.example.com"), (b"origin", b"https://beta.demo.example.com")],
                "subprotocols": [],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    sent_messages = [msg for msg in messages if msg.get("type") == "websocket.send"]
    assert sent_messages and sent_messages[0].get("text") == "background"


@pytest.mark.asyncio
async def test_websocket_utility_methods() -> None:
    sent: list[Mapping[str, object]] = []
    incoming: list[Mapping[str, object]] = [
        {"type": "websocket.receive", "bytes": bytearray(b"raw-data")},
        {"type": "websocket.receive", "text": "hello"},
        {"type": "websocket.receive", "text": '{"value": 1}'},
        {"type": "websocket.receive", "bytes": b'{"value": 2}'},
        {"type": "websocket.receive", "bytes": b"direct-bytes"},
        {"type": "websocket.receive", "bytes": b"not-text"},
        {"type": "websocket.receive", "text": "only-text"},
        {"type": "websocket.disconnect", "code": 1001, "reason": "client closed"},
    ]

    async def receive() -> Mapping[str, object]:
        return incoming.pop(0)

    async def send(message: Mapping[str, object]) -> None:
        sent.append(dict(message))

    tenant = TenantContext(tenant="acme", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(
        method="WEBSOCKET",
        path="/ws",
        headers={},
        tenant=tenant,
        path_params={},
        query_string="",
    )
    executor = TaskExecutor()
    default_disconnect = WebSocketDisconnect()
    assert str(default_disconnect) == "WebSocket disconnected"
    assert default_disconnect.code is None and default_disconnect.reason is None
    socket = WebSocket(
        scope={"type": "websocket", "subprotocols": ["json"]},
        receive=receive,
        send=send,
        request=request,
        executor=executor,
    )

    assert not socket.accepted
    assert not socket.closed
    await socket.accept(subprotocol="json", headers=(("x-test", "true"),))
    await socket.accept()
    assert socket.accepted
    await socket._send_from_result(None)
    await socket.send_bytes(memoryview(b"bytes"))
    await socket.send_json({"payload": True})
    assert await socket.receive_bytes() == b"raw-data"
    assert await socket.receive_text() == "hello"
    assert await socket.receive_json() == {"value": 1}
    assert await socket.receive_json(type=dict) == {"value": 2}
    assert await socket.receive_bytes() == b"direct-bytes"
    with pytest.raises(TypeError):
        await socket.receive_text()
    with pytest.raises(TypeError):
        await socket.receive_bytes()
    dummy = asyncio.create_task(asyncio.sleep(0))
    await dummy
    socket._background.add(dummy)
    await socket.close(code=1002, reason="closing")
    await socket.wait_closed()
    assert socket.closed
    await socket.close()
    with pytest.raises(WebSocketDisconnect) as exc:
        await socket.receive()
    disconnect = cast(WebSocketDisconnect, exc.value)
    assert disconnect.code == 1001
    assert disconnect.reason == "client closed"
    with pytest.raises(RuntimeError):
        await socket._ensure_open()
    await executor.shutdown()

    close_messages = [msg for msg in sent if msg.get("type") == "websocket.close"]
    assert close_messages and close_messages[0].get("code") == 1002


@pytest.mark.asyncio
async def test_websocket_auto_accept_and_fork_behaviour() -> None:
    sent: list[Mapping[str, object]] = []
    incoming: list[Mapping[str, object]] = [
        {"type": "websocket.disconnect", "code": 1000},
    ]

    async def receive() -> Mapping[str, object]:
        return incoming.pop(0)

    async def send(message: Mapping[str, object]) -> None:
        sent.append(dict(message))

    tenant = TenantContext(tenant="beta", site="demo", domain="example.com", scope=TenantScope.TENANT)
    request = Request(method="WEBSOCKET", path="/auto", headers={}, tenant=tenant, path_params={}, query_string="")
    socket = WebSocket(scope={"type": "websocket"}, receive=receive, send=send, request=request)

    await socket.send_text("auto")
    await socket._send_from_result(["extra", b"bytes", {"extra": True}, [1, 2]])
    task = socket.fork(asyncio.sleep, 0)
    await socket.join_background()
    assert task.done()
    with pytest.raises(TypeError):
        socket.fork(lambda: 123)
    with pytest.raises(RuntimeError):
        socket.fork(lambda: "threaded", mode=ExecutionMode.THREAD)
    blocker = asyncio.Event()

    async def stalled() -> None:
        await blocker.wait()

    stalled_task = socket.fork(stalled)
    await socket.close()
    await socket.wait_closed()
    assert stalled_task.cancelled()
    with pytest.raises(WebSocketDisconnect) as exc:
        await socket.receive()
    cast(WebSocketDisconnect, exc.value)
    assert any(msg.get("type") == "websocket.accept" for msg in sent)


@pytest.mark.asyncio
async def test_websocket_missing_host_closes() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app({"type": "websocket", "path": "/ws", "headers": []}, receive, send)
    finally:
        await app.shutdown()

    assert messages and messages[0]["code"] == 4400


@pytest.mark.asyncio
async def test_websocket_unknown_tenant_closes() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [(b"host", b"unknown.demo.example.com"), (b"origin", b"https://unknown.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages and messages[0]["code"] == 4404


@pytest.mark.asyncio
async def test_websocket_route_not_found() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/missing",
                "scheme": "ws",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"http://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages and messages[0]["code"] == 4404


@pytest.mark.asyncio
async def test_websocket_missing_origin_closes() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - missing origin aborts handshake
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [(b"host", b"acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_rejects_non_http_origin() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - invalid origin aborts handshake
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"ftp://acme.demo.example.com"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_rejects_cross_origin() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - cross origin aborts handshake
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"https://evil.example.com"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_rejects_blank_host_value() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - handshake rejected before execution
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"   "),
                    (b"origin", b"https://acme.demo.example.com"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_rejects_origin_with_invalid_port() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - handshake rejected before execution
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"https://acme.demo.example.com:999999"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_rejects_origin_missing_host_component() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - handshake rejected before execution
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"https://:443"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_rejects_blank_origin_value() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - handshake rejected before execution
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"   "),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_rejects_malformed_ipv6_origin() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - handshake rejected before execution
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"https://[::1"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_accepts_sec_websocket_origin_header() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept()
        await socket.close()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"sec-websocket-origin", b"https://acme.demo.example.com:443"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    accept_messages = [msg for msg in messages if msg.get("type") == "websocket.accept"]
    assert accept_messages


@pytest.mark.asyncio
async def test_websocket_accepts_trusted_cross_origin() -> None:
    app = MereApp(
        AppConfig(
            site="demo",
            domain="example.com",
            allowed_tenants=("acme", "beta"),
            websocket_trusted_origins=(
                "   ",
                "https://chat.example.com",
                "https://chat.example.com:8443",
            ),
        )
    )

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept()
        await socket.close()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"https://chat.example.com:8443"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    accept_messages = [msg for msg in messages if msg.get("type") == "websocket.accept"]
    assert accept_messages


@pytest.mark.asyncio
async def test_websocket_secure_scheme_requires_https_origin() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - handshake rejected before execution
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "scheme": "wss",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"http://acme.demo.example.com"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == [{"type": "websocket.close", "code": 4403}]


@pytest.mark.asyncio
async def test_websocket_ws_scheme_accepts_http_origin() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept()
        await socket.close()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "scheme": "ws",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com:80"),
                    (b"origin", b"http://acme.demo.example.com"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    accept_messages = [msg for msg in messages if msg.get("type") == "websocket.accept"]
    assert accept_messages


@pytest.mark.asyncio
async def test_websocket_allows_origin_without_explicit_default_port() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept()
        await socket.close()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "scheme": "wss",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com:443"),
                    (b"origin", b"https://acme.demo.example.com"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    accept_messages = [msg for msg in messages if msg.get("type") == "websocket.accept"]
    assert accept_messages


@pytest.mark.asyncio
async def test_websocket_allows_explicit_default_origin_port() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept()
        await socket.close()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"host", b"acme.demo.example.com"),
                    (b"origin", b"https://acme.demo.example.com:443"),
                ],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    accept_messages = [msg for msg in messages if msg.get("type") == "websocket.accept"]
    assert accept_messages


@pytest.mark.asyncio
async def test_websocket_invalid_initial_message() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - handshake should fail before execution
        await socket.accept()
        await socket.close()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.receive"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages and messages[0]["code"] == 4400


@pytest.mark.asyncio
async def test_websocket_authorization_failure_close() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    guard = RouteGuard(action="chat:open", resource_type="room")

    @app.websocket("/guarded", authorize=guard)
    async def guarded(socket: WebSocket) -> None:  # pragma: no cover - guard blocks execution
        await socket.accept()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/guarded",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages and messages[0]["code"] == 4403


@pytest.mark.asyncio
async def test_websocket_handler_exception_closes() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/boom")
    async def boom(socket: WebSocket) -> None:
        raise ValueError("boom")

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    with pytest.raises(ValueError):
        await app(
            {
                "type": "websocket",
                "path": "/boom",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    await app.shutdown()

    assert messages and messages[0]["code"] == 1011


@pytest.mark.asyncio
async def test_websocket_handler_auto_close() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/auto-close")
    async def auto_close(socket: WebSocket) -> None:
        await socket.accept()

    messages: list[Mapping[str, object]] = []
    incoming = [{"type": "websocket.connect"}]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/auto-close",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    close_messages = [msg for msg in messages if msg.get("type") == "websocket.close"]
    assert close_messages and close_messages[0]["code"] == 1000


@pytest.mark.asyncio
async def test_websocket_handler_disconnect_propagation() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/recv")
    async def recv(socket: WebSocket) -> None:
        await socket.accept()
        await socket.receive()

    messages: list[Mapping[str, object]] = []
    incoming = [
        {"type": "websocket.connect"},
        {"type": "websocket.disconnect", "code": 1000},
    ]

    async def receive() -> Mapping[str, object]:
        return incoming.pop(0)

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/recv",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert any(msg.get("type") == "websocket.accept" for msg in messages)
    assert not any(msg.get("type") == "websocket.close" for msg in messages)


@pytest.mark.asyncio
async def test_websocket_route_argument_injection() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    helper_value = RouteHelper()
    app.dependencies.provide(RouteHelper, lambda: helper_value)

    captured: dict[str, object] = {}

    @app.websocket("/rooms/{room}/{room_id}")
    def room_socket(  # type: ignore[return-type]
        room,
        room_id: int,
        socket: WebSocket,
        request: Request,
        tenant: TenantContext,
        helper: RouteHelper,
    ) -> WebSocket:
        asyncio.get_running_loop().create_task(socket.accept())
        captured.update(
            {
                "room": room,
                "room_id": room_id,
                "path": request.path,
                "tenant": tenant.tenant,
                "helper": helper,
            }
        )
        return socket

    messages: list[Mapping[str, object]] = []
    incoming = [{"type": "websocket.connect"}]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/rooms/main/5",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert captured == {
        "room": "main",
        "room_id": 5,
        "path": "/rooms/main/5",
        "tenant": "acme",
        "helper": helper_value,
    }
    assert any(msg.get("type") == "websocket.close" for msg in messages)


@pytest.mark.asyncio
async def test_websocket_handler_http_error_close() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/http-error")
    async def http_error(socket: WebSocket) -> None:
        await socket.accept()
        raise HTTPError(Status.FORBIDDEN, "blocked")

    messages: list[Mapping[str, object]] = []
    incoming = [{"type": "websocket.connect"}]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/http-error",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    close_messages = [msg for msg in messages if msg.get("type") == "websocket.close"]
    assert close_messages and close_messages[0]["code"] == 4403


@pytest.mark.asyncio
async def test_websocket_missing_dependency_closes() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/missing-dependency")
    async def missing_dependency(helper: RouteHelper, socket: WebSocket) -> None:
        await socket.accept()

    messages: list[Mapping[str, object]] = []
    incoming = [{"type": "websocket.connect"}]

    async def receive() -> Mapping[str, object]:
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/missing-dependency",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    close_messages = [msg for msg in messages if msg.get("type") == "websocket.close"]
    assert close_messages and close_messages[0]["code"] == 1011


@pytest.mark.asyncio
async def test_websocket_disconnect_during_connect() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - disconnect aborts handshake
        await socket.accept()
        await socket.close()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    try:
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    finally:
        await app.shutdown()

    assert messages == []


@pytest.mark.asyncio
async def test_websocket_receive_exception_closes() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:  # pragma: no cover - receive error aborts handshake
        await socket.accept()
        await socket.close()

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        raise RuntimeError("read failure")

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    with pytest.raises(RuntimeError):
        await app(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    await app.shutdown()

    assert messages and messages[0]["code"] == 1011


@pytest.mark.asyncio
async def test_websocket_handler_return_value_error() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))

    @app.websocket("/invalid")
    async def invalid(socket: WebSocket) -> str:
        await socket.accept()
        return "not allowed"

    messages: list[Mapping[str, object]] = []

    async def receive() -> Mapping[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: Mapping[str, object]) -> None:
        messages.append(dict(message))

    await app.startup()
    with pytest.raises(RuntimeError):
        await app(
            {
                "type": "websocket",
                "path": "/invalid",
                "headers": [(b"host", b"acme.demo.example.com"), (b"origin", b"https://acme.demo.example.com")],
            },
            receive,
            send,
        )
    await app.shutdown()

    close_messages = [msg for msg in messages if msg.get("type") == "websocket.close"]
    assert close_messages and close_messages[0]["code"] == 1011


def test_status_to_websocket_close_mappings() -> None:
    assert _status_to_websocket_close(400) == 4400
    assert _status_to_websocket_close(401) == 4401
    assert _status_to_websocket_close(404) == 4404
    assert _status_to_websocket_close(409) == 4400
    assert _status_to_websocket_close(500) == 1011
    assert _status_to_websocket_close(200) == 1008


@pytest.mark.asyncio
async def test_websocket_log_task_error() -> None:
    async def boom() -> None:
        raise RuntimeError("boom")

    task = asyncio.create_task(boom())
    with pytest.raises(RuntimeError):
        await task
    _log_ws_task_error(task)
