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

_PipelineKey = tuple[MiddlewareCallable, ...]
_PIPELINE_CACHE: dict[_PipelineKey, "_MiddlewarePipeline"] = {}


def apply_middleware(
    middlewares: Iterable[MiddlewareCallable],
    endpoint: Handler,
    *,
    observability: "Observability | None" = None,
    request_context: "_ObservationContext | None" = None,
) -> Handler:
    """Compose middleware into a single handler."""

    normalized = _normalize_middlewares(middlewares)
    if not normalized:
        return endpoint
    pipeline = _PIPELINE_CACHE.get(normalized)
    if pipeline is None:
        pipeline = _MiddlewarePipeline(normalized)
        _PIPELINE_CACHE[normalized] = pipeline
    return pipeline.bind(endpoint, observability=observability, request_context=request_context)


def _normalize_middlewares(middlewares: Iterable[MiddlewareCallable]) -> _PipelineKey:
    if isinstance(middlewares, tuple):
        return middlewares
    return tuple(middlewares)


class _MiddlewarePipeline:
    __slots__ = ("_middlewares",)

    def __init__(self, middlewares: _PipelineKey) -> None:
        self._middlewares = middlewares

    def bind(
        self,
        endpoint: Handler,
        *,
        observability: "Observability | None" = None,
        request_context: "_ObservationContext | None" = None,
    ) -> Handler:
        return _BoundPipeline(self, endpoint, observability, request_context)

    async def _invoke(
        self,
        index: int,
        request: Request,
        endpoint: Handler,
        observability: "Observability | None",
        request_context: "_ObservationContext | None",
    ) -> Response:
        if index >= len(self._middlewares):
            return await endpoint(request)
        middleware = self._middlewares[index]
        next_handler = _NextHandler(self, index + 1, endpoint, observability, request_context)
        if observability is None or not observability.enabled:
            return await middleware(request, next_handler)
        context = observability.on_middleware_start(middleware, request, request_context)
        try:
            response = await middleware(request, next_handler)
        except Exception as exc:
            observability.on_middleware_error(context, exc)
            raise
        observability.on_middleware_success(context)
        return response


class _BoundPipeline:
    __slots__ = ("_endpoint", "_observability", "_pipeline", "_request_context")

    def __init__(
        self,
        pipeline: _MiddlewarePipeline,
        endpoint: Handler,
        observability: "Observability | None",
        request_context: "_ObservationContext | None",
    ) -> None:
        self._pipeline = pipeline
        self._endpoint = endpoint
        self._observability = observability
        self._request_context = request_context

    async def __call__(self, request: Request) -> Response:
        return await self._pipeline._invoke(
            0,
            request,
            self._endpoint,
            self._observability,
            self._request_context,
        )


class _NextHandler:
    __slots__ = ("_endpoint", "_index", "_observability", "_pipeline", "_request_context")

    def __init__(
        self,
        pipeline: _MiddlewarePipeline,
        index: int,
        endpoint: Handler,
        observability: "Observability | None",
        request_context: "_ObservationContext | None",
    ) -> None:
        self._pipeline = pipeline
        self._index = index
        self._endpoint = endpoint
        self._observability = observability
        self._request_context = request_context

    async def __call__(self, request: Request) -> Response:
        return await self._pipeline._invoke(
            self._index,
            request,
            self._endpoint,
            self._observability,
            self._request_context,
        )
