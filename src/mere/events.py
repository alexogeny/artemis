"""Server-sent event helpers."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import AsyncIterator, Iterable, Mapping
from typing import Any, Awaitable, Callable, cast

import msgspec

from .execution import ExecutionMode, TaskExecutor
from .http import Status
from .responses import Response, apply_default_security_headers
from .serialization import json_encode

logger = logging.getLogger(__name__)


class ServerSentEvent(msgspec.Struct, frozen=True):
    """Structured representation of a server-sent event payload."""

    data: Any
    event: str | None = None
    event_id: str | None = None
    retry: int | None = None
    json: bool = False


class EventStream:
    """Manage streaming server-sent events to the client."""

    _SENTINEL = object()

    def __init__(self, *, executor: TaskExecutor | None = None) -> None:
        self._queue: asyncio.Queue[bytes | object] = asyncio.Queue()
        self._executor = executor
        self._owns_executor = False
        self._executor_shutdown = False
        self._closed = False
        self._background: set[asyncio.Task[Any]] = set()

    @property
    def closed(self) -> bool:
        return self._closed

    async def send(
        self,
        message: ServerSentEvent | Any,
        *,
        event: str | None = None,
        event_id: str | None = None,
        retry: int | None = None,
        json: bool = False,
    ) -> None:
        """Queue an event for emission to the client."""

        if self._closed:
            raise RuntimeError("EventStream is closed")

        payload = message
        payload_event = event
        payload_id = event_id
        payload_retry = retry
        json_mode = json
        if isinstance(message, ServerSentEvent):
            payload = message.data
            if payload_event is None:
                payload_event = message.event
            if payload_id is None:
                payload_id = message.event_id
            if payload_retry is None:
                payload_retry = message.retry
            json_mode = json_mode or message.json

        text = _coerce_event_text(payload, json=json_mode)
        chunk = _format_sse(text, event=payload_event, event_id=payload_id, retry=payload_retry)
        await self._queue.put(chunk)

    def to_response(
        self,
        *,
        status: int = int(Status.OK),
        headers: Iterable[tuple[str, str]] | None = None,
    ) -> Response:
        """Convert the stream to an :class:`~mere.responses.Response`."""

        default_headers: tuple[tuple[str, str], ...] = (
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
            ("connection", "keep-alive"),
        )
        combined = default_headers + tuple(headers or ())
        response = Response(status=status, headers=combined, body=b"", stream=self._iter_events())
        return apply_default_security_headers(response)

    async def close(self) -> None:
        """Signal the end of the stream."""

        if self._closed:
            return
        self._closed = True
        await self._queue.put(self._SENTINEL)

    def fork(
        self,
        func: Callable[..., Awaitable[Any] | Any],
        *args: Any,
        mode: ExecutionMode | None = None,
        **kwargs: Any,
    ) -> asyncio.Task[Any]:
        """Execute ``func`` in the background and emit any returned events."""

        loop = asyncio.get_running_loop()
        if mode is None:
            result = func(*args, **kwargs)
            if not inspect.isawaitable(result):
                raise TypeError("Background function must be awaitable when mode is None")
            awaitable = _ensure_awaitable(result)
            task = cast(asyncio.Task[Any], asyncio.ensure_future(awaitable))
        else:
            executor = self._ensure_executor()

            async def runner() -> None:
                outcome = await executor.run(func, *args, mode=mode, **kwargs)
                await self._emit_from_result(outcome)

            task = loop.create_task(runner())
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        task.add_done_callback(_log_task_error)
        return task

    async def join_background(self) -> None:
        """Wait for all background tasks to complete."""

        if self._background:
            await asyncio.gather(*tuple(self._background), return_exceptions=True)
        await self._shutdown_executor()

    def _iter_events(self) -> AsyncIterator[bytes]:
        async def iterator() -> AsyncIterator[bytes]:
            try:
                while True:
                    chunk = await self._queue.get()
                    if chunk is self._SENTINEL:
                        break
                    yield chunk  # type: ignore[misc]
            finally:
                await self._finalize()

        return iterator()

    async def _emit_from_result(self, result: Any) -> None:
        if result is None:
            return
        if isinstance(result, ServerSentEvent):
            await self.send(result)
            return
        if isinstance(result, (bytes, bytearray, memoryview)):
            await self.send(bytes(result))
            return
        if isinstance(result, str):
            await self.send(result)
            return
        if isinstance(result, Mapping):
            await self.send(result, json=True)
            return
        if isinstance(result, Iterable) and not isinstance(result, (str, bytes, bytearray, memoryview)):
            for item in result:
                await self._emit_from_result(item)
            return
        await self.send(result, json=True)

    async def _finalize(self) -> None:
        self._closed = True
        pending = [task for task in tuple(self._background) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await self._shutdown_executor()

    def _ensure_executor(self) -> TaskExecutor:
        if self._executor is None:
            self._executor = TaskExecutor()
            self._owns_executor = True
        return self._executor

    async def _shutdown_executor(self) -> None:
        if not self._owns_executor or self._executor is None or self._executor_shutdown:
            return
        await self._executor.shutdown()
        self._executor_shutdown = True


def _coerce_event_text(data: Any, *, json: bool) -> str:
    if json:
        return json_encode(data).decode("utf-8")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).decode("utf-8")
    return str(data)


def _format_sse(
    data: str,
    *,
    event: str | None,
    event_id: str | None,
    retry: int | None,
) -> bytes:
    lines: list[str] = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    if event is not None:
        lines.append(f"event: {event}")
    payload_lines = data.splitlines()
    if not payload_lines:
        payload_lines = [""]
    if data.endswith("\n"):
        payload_lines.append("")
    for line in payload_lines:
        lines.append(f"data: {line}")
    if retry is not None:
        lines.append(f"retry: {retry}")
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def _log_task_error(task: asyncio.Task[Any]) -> None:
    if task.cancelled():
        return
    try:
        error = task.exception()
    except Exception:  # pragma: no cover - defensive
        logger.exception("Background task failed")
        return
    if error is not None:
        logger.exception("Background task failed", exc_info=error)


def _ensure_awaitable(result: Awaitable[Any] | Any) -> Awaitable[Any]:
    if inspect.isawaitable(result):
        return result  # type: ignore[return-value]
    raise TypeError("Expected awaitable result")


__all__ = ["EventStream", "ServerSentEvent"]
