"""Concurrency primitives used by Mere."""

from __future__ import annotations

import asyncio
import importlib
import inspect
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from enum import Enum
from typing import Any, Awaitable, Callable, Iterable, Protocol, TypeVar, cast

import msgspec

from .serialization import msgpack_decode, msgpack_encode

T = TypeVar("T")


class CallableSupportsIntrospection(Protocol):
    __module__: str
    __qualname__: str

    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...


class ExecutionMode(str, Enum):
    """Supported execution modes for offloading work."""

    THREAD = "thread"
    PROCESS = "process"
    REMOTE = "remote"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class ExecutionConfig(msgspec.Struct, frozen=True):
    """Configuration for :class:`TaskExecutor`."""

    default_mode: ExecutionMode = ExecutionMode.THREAD
    max_workers: int = 4
    remote_endpoint: str | None = None


class TaskExecutor:
    """Asynchronous executor capable of thread, process, and remote execution."""

    def __init__(self, config: ExecutionConfig | None = None) -> None:
        self.config = config or ExecutionConfig()
        self._thread_pool: ThreadPoolExecutor | None = None
        self._process_pool: ProcessPoolExecutor | None = None

    async def __aenter__(self) -> "TaskExecutor":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.shutdown()

    async def run(
        self,
        func: Callable[..., Awaitable[T]] | Callable[..., T],
        *args: Any,
        mode: ExecutionMode | None = None,
        **kwargs: Any,
    ) -> T:
        """Execute ``func`` in the desired execution mode."""

        chosen_mode = mode or self.config.default_mode
        if chosen_mode == ExecutionMode.REMOTE:
            return await self._run_remote(func, args, kwargs)

        if inspect.iscoroutinefunction(func):
            coroutine = cast(Callable[..., Awaitable[T]], func)
            return await coroutine(*args, **kwargs)

        loop = asyncio.get_running_loop()
        if chosen_mode == ExecutionMode.THREAD:
            pool = self._thread_pool or ThreadPoolExecutor(max_workers=self.config.max_workers)
            self._thread_pool = pool
            return await loop.run_in_executor(pool, _invoke_callable, func, args, kwargs)
        if chosen_mode == ExecutionMode.PROCESS:
            pool = self._process_pool or ProcessPoolExecutor(max_workers=self.config.max_workers)
            self._process_pool = pool
            return await loop.run_in_executor(pool, _invoke_callable, func, args, kwargs)
        raise ValueError(f"Unsupported execution mode: {chosen_mode}")

    async def shutdown(self) -> None:
        """Shutdown all backing executors."""

        if self._thread_pool is not None:
            self._thread_pool.shutdown(wait=False, cancel_futures=True)
            self._thread_pool = None
        if self._process_pool is not None:
            self._process_pool.shutdown(wait=False, cancel_futures=True)
            self._process_pool = None

    async def _run_remote(
        self,
        func: Callable[..., Awaitable[T]] | Callable[..., T],
        args: Iterable[Any],
        kwargs: dict[str, Any],
    ) -> T:
        """Simulate remote execution via msgspec msgpack serialization."""

        if inspect.iscoroutinefunction(func):
            coroutine = cast(Callable[..., Awaitable[T]], func)
            return await coroutine(*args, **kwargs)

        target = _call_target(cast(CallableSupportsIntrospection, func))
        payload = msgpack_encode((target, tuple(args), kwargs))
        loop = asyncio.get_running_loop()
        encoded = await loop.run_in_executor(None, _simulate_remote_call, payload)
        return cast(T, msgpack_decode(encoded))


def _invoke_callable(func: Callable[..., T], args: tuple[Any, ...], kwargs: dict[str, Any]) -> T:
    return func(*args, **kwargs)


def _call_target(func: CallableSupportsIntrospection) -> tuple[str, str]:
    module = func.__module__
    qualname = func.__qualname__
    return module, qualname


def _simulate_remote_call(payload: bytes) -> bytes:
    target, args, kwargs = cast(tuple[tuple[str, str], tuple[Any, ...], dict[str, Any]], msgpack_decode(payload))
    module_name, qualname = target
    module = importlib.import_module(module_name)
    target_callable = cast(Any, module)
    for part in qualname.split("."):
        target_callable = getattr(target_callable, part)
    callable_target = cast(Callable[..., Any], target_callable)
    result = callable_target(*args, **kwargs)
    return msgpack_encode(result)
