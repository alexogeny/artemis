"""Application core."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Dict, Iterable, Mapping, Sequence

import msgspec

from .chatops import ChatOpsService
from .config import AppConfig
from .database import Database
from .dependency import DependencyProvider
from .exceptions import HTTPError
from .execution import TaskExecutor
from .middleware import MiddlewareCallable, apply_middleware
from .orm import ORM
from .rbac import CedarEngine, CedarEntity
from .requests import Request
from .responses import JSONResponse, PlainTextResponse, Response, exception_to_response
from .routing import RouteGuard, Router
from .tenancy import TenantContext, TenantResolver
from .typing_utils import convert_primitive

Handler = Callable[[Request], Awaitable[Response]]


class ArtemisApp:
    """Central application object."""

    def __init__(
        self,
        config: AppConfig | None = None,
        *,
        dependency_provider: DependencyProvider | None = None,
        executor: TaskExecutor | None = None,
        tenant_resolver: TenantResolver | None = None,
        database: Database | None = None,
        orm: ORM | None = None,
        chatops: ChatOpsService | None = None,
    ) -> None:
        self.config = config or AppConfig()
        self.router = Router()
        self.dependencies = dependency_provider or DependencyProvider()
        self.executor = executor or TaskExecutor(self.config.execution)
        self.tenant_resolver = tenant_resolver or TenantResolver(
            site=self.config.site,
            domain=self.config.domain,
            admin_subdomain=self.config.admin_subdomain,
            marketing_tenant=self.config.marketing_tenant,
            allowed_tenants=self.config.allowed_tenants or None,
        )
        self.database = database or (Database(self.config.database) if self.config.database else None)
        self.orm = orm or (ORM(self.database) if self.database else None)
        self.chatops = chatops or ChatOpsService(self.config.chatops)
        self._middlewares: list[MiddlewareCallable] = []
        self._startup_hooks: list[Callable[[], Awaitable[None] | None]] = []
        self._shutdown_hooks: list[Callable[[], Awaitable[None] | None]] = []
        self._named_routes: dict[str, str] = {}

        if self.database:
            self.dependencies.provide(Database, lambda: self.database)
            self.on_startup(self.database.startup)
            self.on_shutdown(self.database.shutdown)
        if self.orm:
            self.dependencies.provide(ORM, lambda: self.orm)
        self.dependencies.provide(ChatOpsService, lambda: self.chatops)

    # ------------------------------------------------------------------ routing
    def route(
        self,
        path: str,
        *,
        methods: Iterable[str],
        name: str | None = None,
        authorize: RouteGuard | Sequence[RouteGuard] | None = None,
    ) -> Callable[[Callable[..., Awaitable[Any] | Any]], Callable[..., Awaitable[Any] | Any]]:
        def decorator(func: Callable[..., Awaitable[Any] | Any]) -> Callable[..., Awaitable[Any] | Any]:
            guards = self._normalize_guards(authorize)
            self.router.add_route(path, methods=tuple(methods), endpoint=func, name=name, guards=guards)
            if name is not None:
                self._named_routes[name] = path
            return func

        return decorator

    def get(
        self,
        path: str,
        *,
        name: str | None = None,
        authorize: RouteGuard | Sequence[RouteGuard] | None = None,
    ) -> Callable[[Callable[..., Awaitable[Any] | Any]], Callable[..., Awaitable[Any] | Any]]:
        return self.route(path, methods=("GET",), name=name, authorize=authorize)

    def post(
        self,
        path: str,
        *,
        name: str | None = None,
        authorize: RouteGuard | Sequence[RouteGuard] | None = None,
    ) -> Callable[[Callable[..., Awaitable[Any] | Any]], Callable[..., Awaitable[Any] | Any]]:
        return self.route(path, methods=("POST",), name=name, authorize=authorize)

    def include(self, *handlers: Callable[..., Awaitable[Any] | Any]) -> None:
        self.router.include(handlers)

    def guard(self, *guards: RouteGuard) -> None:
        self.router.guard(*guards)

    def url_path_for(self, name: str, /, **params: Any) -> str:
        template = self._named_routes.get(name)
        if template is None:
            raise LookupError(f"Route {name!r} not found")
        path = template
        for key, value in params.items():
            path = path.replace(f"{{{key}}}", str(value))
        return path

    # ------------------------------------------------------------------ middleware
    def add_middleware(self, middleware: MiddlewareCallable) -> None:
        self._middlewares.append(middleware)

    # ------------------------------------------------------------------ lifecycle
    def on_startup(self, func: Callable[[], Awaitable[None] | None]) -> Callable[[], Awaitable[None] | None]:
        self._startup_hooks.append(func)
        return func

    def on_shutdown(self, func: Callable[[], Awaitable[None] | None]) -> Callable[[], Awaitable[None] | None]:
        self._shutdown_hooks.append(func)
        return func

    async def startup(self) -> None:
        for hook in self._startup_hooks:
            result = hook()
            if inspect.isawaitable(result):
                await result

    async def shutdown(self) -> None:
        for hook in self._shutdown_hooks:
            result = hook()
            if inspect.isawaitable(result):
                await result
        await self.executor.shutdown()

    # ------------------------------------------------------------------ request handling
    async def dispatch(
        self,
        method: str,
        path: str,
        *,
        host: str,
        query_string: str | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> Response:
        tenant = self.tenant_resolver.resolve(host)
        match = self.router.find(method, path)
        request = Request(
            method=method,
            path=path,
            headers=headers or {},
            tenant=tenant,
            path_params=match.params,
            query_string=query_string or "",
            body=body or b"",
        )
        scope = self.dependencies.scope(request)

        async def endpoint_handler(req: Request) -> Response:
            return await self._execute_route(match.route, req, scope)

        handler = apply_middleware(self._middlewares, endpoint_handler)
        try:
            return await handler(request)
        except HTTPError as exc:
            return exception_to_response(exc)

    async def _execute_route(self, route, request: Request, scope) -> Response:
        await self._authorize_route(route, request, scope)
        call_args: Dict[str, Any] = {}
        body_payload: Any | None = None
        for name, parameter in route.signature.parameters.items():
            annotation = route.type_hints.get(name, parameter.annotation)
            if annotation is inspect.Signature.empty:
                annotation = str if name in route.param_names else Any
            if annotation is Request:
                call_args[name] = request
                continue
            if annotation is TenantContext:
                call_args[name] = request.tenant
                continue
            if name in route.param_names:
                value = request.path_params[name]
                if annotation is str or annotation is Any:
                    call_args[name] = value
                else:
                    call_args[name] = convert_primitive(value, annotation, source=name)
                continue
            try:
                call_args[name] = await scope.get(annotation)
            except LookupError as exc:
                if _is_struct(annotation):
                    if body_payload is None:
                        body_payload = await request.json()
                    call_args[name] = msgspec.convert(body_payload or {}, type=annotation)
                else:
                    raise HTTPError(500, {"dependency": repr(annotation), "detail": str(exc)})
        result = route.spec.endpoint(**call_args)
        if inspect.isawaitable(result):
            result = await result
        return _coerce_response(result)

    async def _authorize_route(self, route, request: Request, scope) -> None:
        if not route.guards:
            return
        principal = request.principal
        if principal is None:
            raise HTTPError(403, {"detail": "authentication_required"})
        try:
            engine = await scope.get(CedarEngine)
        except LookupError as exc:  # pragma: no cover - dependency misconfiguration
            raise HTTPError(500, {"detail": "authorization engine missing"}) from exc
        for guard in route.guards:
            if guard.principal_type not in ("*", principal.type):
                raise HTTPError(403, {"detail": "principal_not_allowed", "required": guard.principal_type})
            resource_id = guard.resolve_resource(request)
            resource = CedarEntity(guard.resource_type, resource_id) if resource_id else None
            context = guard.context(request)
            allowed = engine.check(
                principal=principal,
                action=guard.action,
                resource=resource,
                context=context,
            )
            if not allowed:
                raise HTTPError(
                    403,
                    {
                        "action": guard.action,
                        "resource_type": guard.resource_type,
                        "resource_id": resource_id,
                        "detail": "forbidden",
                    },
                )

    @staticmethod
    def _normalize_guards(authorize: RouteGuard | Sequence[RouteGuard] | None) -> tuple[RouteGuard, ...]:
        if authorize is None:
            return ()
        if isinstance(authorize, RouteGuard):
            return (authorize,)
        return tuple(authorize)

    # ------------------------------------------------------------------ interface adapters
    async def __call__(
        self,
        scope: Mapping[str, Any],
        receive: Callable[[], Awaitable[Mapping[str, Any]]],
        send: Callable[[Mapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("ArtemisApp only supports HTTP scopes")
        headers = {
            key.decode().lower(): value.decode()
            for key, value in scope.get("headers", [])
        }
        host = headers.get("host")
        if host is None:
            raise RuntimeError("Host header required for multi-tenant resolution")
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                continue
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
        response = await self.dispatch(
            scope["method"],
            scope["path"],
            host=host,
            query_string=(scope.get("query_string") or b"").decode(),
            headers=headers,
            body=body,
        )
        await send({
            "type": "http.response.start",
            "status": response.status,
            "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in response.headers],
        })
        await send({
            "type": "http.response.body",
            "body": response.body,
        })


class Artemis(ArtemisApp):
    """Convenience subclass exposing configuration helpers."""

    @classmethod
    def from_config(cls, config: AppConfig | Mapping[str, Any]) -> "Artemis":
        if isinstance(config, AppConfig):
            return cls(config=config)
        return cls(config=msgspec.convert(config, type=AppConfig))


def _is_struct(annotation: Any) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, msgspec.Struct)


def _coerce_response(result: Any) -> Response:
    if isinstance(result, Response):
        return result
    if result is None:
        return Response(status=204, body=b"")
    if isinstance(result, str):
        return PlainTextResponse(result)
    return JSONResponse(result)
