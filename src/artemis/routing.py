"""Routing utilities."""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Mapping, MutableMapping, Sequence, get_type_hints

import rure
from rure.regex import RegexObject

Endpoint = Callable[..., Awaitable[Any] | Any]


@dataclass(slots=True)
class RouteSpec:
    path: str
    methods: tuple[str, ...]
    endpoint: Endpoint
    name: str | None = None


@dataclass(slots=True)
class Route:
    spec: RouteSpec
    pattern: RegexObject
    param_names: tuple[str, ...]
    signature: inspect.Signature
    type_hints: Mapping[str, Any]


@dataclass(slots=True)
class RouteMatch:
    route: Route
    params: Mapping[str, str]


class Router:
    def __init__(self) -> None:
        self._routes: list[Route] = []

    def add_route(
        self,
        path: str,
        *,
        methods: Sequence[str],
        endpoint: Endpoint,
        name: str | None = None,
    ) -> Route:
        pattern, param_names = _compile_path(path)
        spec = RouteSpec(path=path, methods=tuple(m.upper() for m in methods), endpoint=endpoint, name=name)
        hints = get_type_hints(endpoint)
        route = Route(
            spec=spec,
            pattern=pattern,
            param_names=param_names,
            signature=inspect.signature(endpoint),
            type_hints=hints,
        )
        self._routes.append(route)
        return route

    def find(self, method: str, path: str) -> RouteMatch:
        method = method.upper()
        for route in self._routes:
            if method not in route.spec.methods:
                continue
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
            self.add_route(spec.path, methods=spec.methods, endpoint=handler, name=spec.name)


def route(path: str, *, methods: Sequence[str], name: str | None = None) -> Callable[[Endpoint], Endpoint]:
    def decorator(func: Endpoint) -> Endpoint:
        spec = RouteSpec(path=path, methods=tuple(methods), endpoint=func, name=name)
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
        param_names.append(name)
        return f"(?P<{name}>[^/]+)"

    pattern = "^" + re.sub(r"{([a-zA-Z_][a-zA-Z0-9_]*)}", replace, path) + "$"
    return rure.compile(pattern), tuple(param_names)
