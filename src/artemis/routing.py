"""Routing utilities."""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Iterable,
    Mapping,
    MutableMapping,
    Sequence,
    get_type_hints,
)

import rure
from rure.regex import RegexObject

if TYPE_CHECKING:
    from .requests import Request

Endpoint = Callable[..., Awaitable[Any] | Any]


_PATH_PARAM_PATTERN = re.compile(r"{([a-zA-Z_][a-zA-Z0-9_]*)(?::([a-zA-Z_][a-zA-Z0-9_]*))?}")


@dataclass(slots=True)
class RouteSpec:
    path: str
    methods: tuple[str, ...]
    endpoint: Endpoint
    name: str | None = None
    guards: tuple["RouteGuard", ...] = ()


@dataclass(slots=True)
class Route:
    spec: RouteSpec
    pattern: RegexObject
    param_names: tuple[str, ...]
    signature: inspect.Signature
    type_hints: Mapping[str, Any]
    guards: tuple["RouteGuard", ...]


@dataclass(slots=True)
class RouteMatch:
    route: Route
    params: Mapping[str, str]


@dataclass(slots=True, frozen=True)
class RouteGuard:
    action: str
    resource_type: str
    resource_id: str | Callable[["Request"], str | None] | None = None
    principal_type: str = "*"
    context_factory: Callable[["Request"], Mapping[str, Any]] | Mapping[str, Any] | None = None

    def context(self, request: "Request") -> Mapping[str, Any] | None:
        if callable(self.context_factory):
            return self.context_factory(request)
        return self.context_factory

    def resolve_resource(self, request: "Request") -> str | None:
        if callable(self.resource_id):
            return self.resource_id(request)
        return self.resource_id


class Router:
    def __init__(self) -> None:
        self._routes: list[Route] = []
        self._routes_by_method: dict[str, list[Route]] = {}
        self._global_guards: list[RouteGuard] = []

    def add_route(
        self,
        path: str,
        *,
        methods: Sequence[str],
        endpoint: Endpoint,
        name: str | None = None,
        guards: Sequence[RouteGuard] | None = None,
    ) -> Route:
        pattern, param_names = _compile_path(path)
        guard_tuple = tuple(guards or ())
        normalized_methods = tuple(dict.fromkeys(m.upper() for m in methods))
        spec = RouteSpec(
            path=path,
            methods=normalized_methods,
            endpoint=endpoint,
            name=name,
            guards=guard_tuple,
        )
        hints = get_type_hints(endpoint)
        route = Route(
            spec=spec,
            pattern=pattern,
            param_names=param_names,
            signature=inspect.signature(endpoint),
            type_hints=hints,
            guards=tuple(self._global_guards) + guard_tuple,
        )
        self._routes.append(route)
        for method in normalized_methods:
            self._routes_by_method.setdefault(method, []).append(route)
        return route

    def guard(self, *guards: RouteGuard) -> None:
        self._global_guards.extend(guards)

    def find(self, method: str, path: str) -> RouteMatch:
        method = method.upper()
        candidates = self._routes_by_method.get(method)
        if not candidates:
            candidates = self._routes_by_method.get("*")
            if not candidates:
                raise LookupError(f"No route matches {method} {path}")
        for route in candidates:
            captures = route.pattern.match(path)
            if captures is None:
                continue
            params: MutableMapping[str, str] = {}
            for name in route.param_names:
                group = captures.group(name)
                if group is None:
                    continue
                params[name] = group
            return RouteMatch(route=route, params=params)
        raise LookupError(f"No route matches {method} {path}")

    def include(self, handlers: Iterable[Endpoint]) -> None:
        for handler in handlers:
            spec: RouteSpec | None = getattr(handler, "__artemis_route__", None)
            if spec is None:
                raise ValueError(f"Handler {handler!r} missing @route decorator metadata")
            self.add_route(spec.path, methods=spec.methods, endpoint=handler, name=spec.name, guards=spec.guards)


def route(
    path: str,
    *,
    methods: Sequence[str],
    name: str | None = None,
    authorize: RouteGuard | Sequence[RouteGuard] | None = None,
) -> Callable[[Endpoint], Endpoint]:
    def decorator(func: Endpoint) -> Endpoint:
        if authorize is None:
            guards: tuple[RouteGuard, ...] = ()
        elif isinstance(authorize, RouteGuard):
            guards = (authorize,)
        else:
            guards = tuple(authorize)
        spec = RouteSpec(path=path, methods=tuple(methods), endpoint=func, name=name, guards=guards)
        setattr(func, "__artemis_route__", spec)
        return func

    return decorator


def get(path: str, *, name: str | None = None) -> Callable[[Endpoint], Endpoint]:
    return route(path, methods=["GET"], name=name)


def post(path: str, *, name: str | None = None) -> Callable[[Endpoint], Endpoint]:
    return route(path, methods=["POST"], name=name)


def _compile_path(path: str) -> tuple[RegexObject, tuple[str, ...]]:
    param_names: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        converter = match.group(2)
        param_names.append(name)
        if converter is None:
            return f"(?P<{name}>[^/]+)"
        if converter == "path":
            return f"(?P<{name}>.*)"
        raise ValueError(f"Unsupported path converter: {converter}")

    pattern = "^" + _PATH_PARAM_PATTERN.sub(replace, path) + "$"
    return rure.compile(pattern), tuple(param_names)
