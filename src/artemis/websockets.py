"""WebSocket utilities."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Iterable, Mapping
from typing import Any, Awaitable, Callable, TypeVar, cast

import msgspec

from .execution import ExecutionMode, TaskExecutor
from .requests import Request
from .serialization import json_decode, json_encode

logger = logging.getLogger(__name__)

T = TypeVar("T")


class WebSocketDisconnect(Exception):
    """Raised when the client disconnects from the WebSocket."""

    def __init__(self, code: int | None = None, reason: str | None = None) -> None:
        message = "WebSocket disconnected"
        if code is not None:
            message = f"{message} ({code})"
        if reason:
            message = f"{message}: {reason}"
        super().__init__(message)
        self.code = code
        self.reason = reason


class WebSocket:
    """Asynchronous helper around the ASGI WebSocket interface."""

    def __init__(
        self,
        *,
        scope: Mapping[str, Any],
        receive: Callable[[], Awaitable[Mapping[str, Any]]],
        send: Callable[[Mapping[str, Any]], Awaitable[None]],
        request: Request,
        executor: TaskExecutor | None = None,
    ) -> None:
        self.scope = scope
        self._receive = receive
        self._send = send
        self.request = request
        self._executor = executor
        self._accepted = False
        self._closed = False
        self._close_event = asyncio.Event()
        self._background: set[asyncio.Task[Any]] = set()
        self.subprotocols: tuple[str, ...] = tuple(scope.get("subprotocols") or ())

    @property
    def accepted(self) -> bool:
        return self._accepted

    @property
    def closed(self) -> bool:
        return self._closed

    async def accept(
        self,
        *,
        subprotocol: str | None = None,
        headers: Iterable[tuple[str, str]] | None = None,
    ) -> None:
        if self._accepted:
            return
        message: dict[str, Any] = {"type": "websocket.accept"}
        if subprotocol is not None:
            message["subprotocol"] = subprotocol
        if headers:
            message["headers"] = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers]
        await self._send(message)
        self._accepted = True

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        if self._closed:
            return
        payload: dict[str, Any] = {"type": "websocket.close", "code": code}
        if reason:
            payload["reason"] = reason
        await self._send(payload)
        self._closed = True
        self._close_event.set()
        await self._cancel_background()

    async def wait_closed(self) -> None:
        await self._close_event.wait()

    async def receive(self) -> Mapping[str, Any]:
        message = await self._receive()
        message_type = message.get("type")
        if message_type == "websocket.disconnect":
            self._closed = True
            self._close_event.set()
            await self._cancel_background()
            raise WebSocketDisconnect(
                code=cast(int | None, message.get("code")),
                reason=cast(str | None, message.get("reason")),
            )
        return message

    async def receive_text(self) -> str:
        message = await self.receive()
        text = message.get("text")
        if text is None:
            raise TypeError("Expected text WebSocket frame")
        return cast(str, text)

    async def receive_bytes(self) -> bytes:
        message = await self.receive()
        data = message.get("bytes")
        if data is None:
            raise TypeError("Expected binary WebSocket frame")
        if isinstance(data, bytes):
            return data
        return bytes(cast(bytearray | memoryview, data))

    async def receive_json(self, type: type[T] | None = None) -> T | Any:
        message = await self.receive()
        text = message.get("text")
        if text is not None:
            payload = json_decode(text.encode("utf-8"))
        else:
            binary = message.get("bytes") or b""
            payload = json_decode(cast(bytes, binary))
        if type is None:
            return payload
        return msgspec.convert(payload, type=type)

    async def send_text(self, data: str) -> None:
        await self._ensure_open()
        await self._ensure_accepted()
        await self._send({"type": "websocket.send", "text": data})

    async def send_bytes(self, data: bytes | bytearray | memoryview) -> None:
        await self._ensure_open()
        await self._ensure_accepted()
        await self._send({"type": "websocket.send", "bytes": bytes(data)})

    async def send_json(self, data: Any) -> None:
        await self._ensure_open()
        await self._ensure_accepted()
        payload = json_encode(data).decode("utf-8")
        await self._send({"type": "websocket.send", "text": payload})

    def fork(
        self,
        func: Callable[..., Awaitable[Any] | Any],
        *args: Any,
        mode: ExecutionMode | None = None,
        **kwargs: Any,
    ) -> asyncio.Task[Any]:
        loop = asyncio.get_running_loop()
        if mode is None:
            result = func(*args, **kwargs)
            awaitable = _ensure_awaitable(result)
            task = cast(asyncio.Task[Any], asyncio.ensure_future(awaitable))
        else:
            if self._executor is None:
                raise RuntimeError("TaskExecutor not configured for WebSocket background tasks")

            async def runner() -> None:
                outcome = await self._executor.run(func, *args, mode=mode, **kwargs)
                await self._send_from_result(outcome)
            task = loop.create_task(runner())
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        task.add_done_callback(_log_task_error)
        return task

    async def join_background(self) -> None:
        if not self._background:
            return
        await asyncio.gather(*tuple(self._background), return_exceptions=True)

    async def _ensure_accepted(self) -> None:
        if not self._accepted:
            await self.accept()

    async def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("WebSocket connection is closed")

    async def _send_from_result(self, result: Any) -> None:
        if result is None:
            return
        if isinstance(result, str):
            await self.send_text(result)
            return
        if isinstance(result, (bytes, bytearray, memoryview)):
            await self.send_bytes(result)
            return
        if isinstance(result, Mapping):
            await self.send_json(result)
            return
        if isinstance(result, Iterable) and not isinstance(result, (str, bytes, bytearray, memoryview)):
            for item in result:
                await self._send_from_result(item)
            return
        await self.send_json(result)

    async def _cancel_background(self) -> None:
        if not self._background:
            return
        pending = [task for task in tuple(self._background) if not task.done()]
        if not pending:
            return
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


def _log_task_error(task: asyncio.Task[Any]) -> None:
    if task.cancelled():
        return
    try:
        error = task.exception()
    except Exception:  # pragma: no cover - defensive logging
        logger.exception("WebSocket background task failed")
        return
    if error is not None:
        logger.exception("WebSocket background task failed", exc_info=error)


def _ensure_awaitable(result: Awaitable[Any] | Any) -> Awaitable[Any]:
    if inspect.isawaitable(result):
        return result
    raise TypeError("Background function must be awaitable when mode is None")


__all__ = ["WebSocket", "WebSocketDisconnect"]
