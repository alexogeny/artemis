"""Middleware chaining primitives."""

from __future__ import annotations

from typing import Awaitable, Callable, Iterable, Protocol

from .requests import Request
from .responses import Response

Handler = Callable[[Request], Awaitable[Response]]


class Middleware(Protocol):
    async def __call__(self, request: Request, handler: Handler) -> Response:  # pragma: no cover - protocol
        ...


MiddlewareCallable = Callable[[Request, Handler], Awaitable[Response]]


def apply_middleware(middlewares: Iterable[MiddlewareCallable], endpoint: Handler) -> Handler:
    """Compose middleware into a single handler."""

    composed = endpoint
    for middleware in reversed(tuple(middlewares)):
        composed = _wrap_middleware(middleware, composed)
    return composed


def _wrap_middleware(middleware: MiddlewareCallable, handler: Handler) -> Handler:
    async def wrapped(request: Request) -> Response:
        return await middleware(request, handler)

    return wrapped
