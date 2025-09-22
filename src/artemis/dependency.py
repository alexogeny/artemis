"""Dependency injection primitives."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Dict, TypeVar, get_type_hints

from .requests import Request
from .tenancy import TenantContext

T = TypeVar("T")
FactoryT = TypeVar("FactoryT", bound=Callable[..., Any])
DependencyCallable = Callable[..., Awaitable[Any] | Any]


class DependencyProvider:
    """Registry for request-scoped dependencies."""

    def __init__(self) -> None:
        self._providers: Dict[type[Any], DependencyCallable] = {}

    def register(self, dependency_type: type[T]) -> Callable[[FactoryT], FactoryT]:
        """Decorator to register a dependency provider."""

        def decorator(factory: FactoryT) -> FactoryT:
            self._providers[dependency_type] = factory
            return factory

        return decorator

    def provide(self, dependency_type: type[T], factory: DependencyCallable) -> None:
        self._providers[dependency_type] = factory

    def scope(self, request: Request) -> "DependencyScope":
        return DependencyScope(self._providers, request)


class DependencyScope:
    """Resolve dependencies for a given :class:`~artemis.requests.Request`."""

    def __init__(self, providers: Dict[type[Any], DependencyCallable], request: Request) -> None:
        self._providers = providers
        self._request = request
        self._cache: Dict[type[Any], Any] = {}

    async def get(self, dependency_type: type[T]) -> T:
        if dependency_type is Request:
            return self._request  # type: ignore[return-value]
        if dependency_type is TenantContext:
            return self._request.tenant  # type: ignore[return-value]
        if dependency_type in self._cache:
            return self._cache[dependency_type]
        factory = self._providers.get(dependency_type)
        if factory is None:
            raise LookupError(f"No dependency registered for {dependency_type!r}")
        result = factory(**await self._build_arguments(factory))
        if inspect.isawaitable(result):
            result = await result
        self._cache[dependency_type] = result
        return result

    async def _build_arguments(self, factory: DependencyCallable) -> Dict[str, Any]:
        signature = inspect.signature(factory)
        hints = get_type_hints(factory)
        arguments: Dict[str, Any] = {}
        for name, param in signature.parameters.items():
            annotation = hints.get(name, param.annotation)
            if annotation is inspect.Signature.empty:
                raise TypeError(f"Dependency factory {factory} is missing typing for parameter {name}")
            if annotation is Request:
                arguments[name] = self._request
            elif annotation is TenantContext:
                arguments[name] = self._request.tenant
            else:
                arguments[name] = await self.get(annotation)
        return arguments
