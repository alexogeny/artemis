"""Middleware chaining primitives."""

from __future__ import annotations

from typing import TYPE_CHECKING, Awaitable, Callable, Iterable, Protocol

from .requests import Request
from .responses import Response

Handler = Callable[[Request], Awaitable[Response]]


if TYPE_CHECKING:  # pragma: no cover - typing only
    from .observability import Observability, _ObservationContext


class Middleware(Protocol):
    async def __call__(self, request: Request, handler: Handler) -> Response:  # pragma: no cover - protocol
        ...


MiddlewareCallable = Callable[[Request, Handler], Awaitable[Response]]


def apply_middleware(
    middlewares: Iterable[MiddlewareCallable],
    endpoint: Handler,
    *,
    observability: "Observability | None" = None,
    request_context: "_ObservationContext | None" = None,
) -> Handler:
    """Compose middleware into a single handler."""

    composed = endpoint
    for middleware in reversed(tuple(middlewares)):
        composed = _wrap_middleware(
            middleware,
            composed,
            observability=observability,
            request_context=request_context,
        )
    return composed


def _wrap_middleware(
    middleware: MiddlewareCallable,
    handler: Handler,
    *,
    observability: "Observability | None" = None,
    request_context: "_ObservationContext | None" = None,
) -> Handler:
    async def wrapped(request: Request) -> Response:
        if observability is None or not observability.enabled:
            return await middleware(request, handler)
        context = observability.on_middleware_start(middleware, request, request_context)
        try:
            response = await middleware(request, handler)
        except Exception as exc:
            observability.on_middleware_error(context, exc)
            raise
        observability.on_middleware_success(context)
        return response

    return wrapped
