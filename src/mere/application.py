"""Application core."""

from __future__ import annotations

import inspect
import os
from collections.abc import AsyncIterable, AsyncIterator
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

import msgspec

from .audit import AuditActor, AuditTrail, audit_context
from .chatops import ChatOpsCommandBinding, ChatOpsCommandRegistry, ChatOpsService, ChatOpsSlashCommand
from .config import AppConfig
from .database import Database
from .dependency import DependencyProvider
from .events import EventStream
from .exceptions import HTTPError
from .execution import TaskExecutor
from .http import Status
from .middleware import MiddlewareCallable, apply_middleware
from .observability import Observability
from .orm import ORM
from .rbac import CedarEngine, CedarEntity
from .requests import Request
from .responses import (
    JSONResponse,
    PlainTextResponse,
    Response,
    apply_default_security_headers,
    exception_to_response,
    security_headers_middleware,
)
from .routing import RouteGuard, Router
from .static import StaticFiles
from .tenancy import TenantContext, TenantResolutionError, TenantResolver
from .typing_utils import convert_primitive
from .websockets import WebSocket, WebSocketDisconnect

Handler = Callable[[Request], Awaitable[Response]]

HeaderPart = bytes | bytearray | memoryview | str

ASGIApp = Callable[
    [Mapping[str, Any], Callable[[], Awaitable[Mapping[str, Any]]], Callable[[Mapping[str, Any]], Awaitable[None]]],
    Awaitable[None],
]

_ALL_HTTP_METHODS: tuple[str, ...] = ("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE")


if TYPE_CHECKING:  # pragma: no cover - typing-only import to avoid circular reference
    from .bootstrap import BootstrapAuthConfig


class MereApp:
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
        observability: Observability | None = None,
        bootstrap_enabled: bool = True,
        bootstrap_auth: "BootstrapAuthConfig | None" = None,
        bootstrap_environment: str | None = None,
        bootstrap_base_path: str = "/__mere",
        bootstrap_allow_production: bool = False,
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
        self.observability = observability or Observability(self.config.observability)
        self.chatops = chatops or ChatOpsService(self.config.chatops, observability=self.observability)
        self.chatops_commands = ChatOpsCommandRegistry()
        if self.database:
            existing_audit = self.orm and getattr(self.orm, "_audit_trail", None)
            if existing_audit is not None:
                self.audit_trail = existing_audit
            else:
                self.audit_trail = AuditTrail(
                    self.database,
                    registry=self.orm.registry if self.orm else None,
                )
                if self.orm:
                    self.orm.attach_audit_trail(self.audit_trail)
        else:
            self.audit_trail = None
        self._middlewares: list[MiddlewareCallable] = []
        self.add_middleware(security_headers_middleware)
        self._startup_hooks: list[Callable[[], Awaitable[None] | None]] = []
        self._shutdown_hooks: list[Callable[[], Awaitable[None] | None]] = []
        self._named_routes: dict[str, str] = {}

        if self.database:
            self.dependencies.provide(Database, lambda: self.database)
            self.on_startup(self.database.startup)
            self.on_shutdown(self.database.shutdown)
        if self.orm:
            self.dependencies.provide(ORM, lambda: self.orm)
        if self.audit_trail:
            self.dependencies.provide(AuditTrail, lambda: self.audit_trail)
        self.dependencies.provide(Observability, lambda: self.observability)
        self.dependencies.provide(ChatOpsService, lambda: self.chatops)

        if bootstrap_enabled:
            from . import bootstrap as _bootstrap

            _bootstrap.attach_bootstrap(
                self,
                base_path=bootstrap_base_path,
                environment=bootstrap_environment,
                allow_production=bootstrap_allow_production,
                auth_config=bootstrap_auth,
            )

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

    def sse(
        self,
        path: str,
        *,
        name: str | None = None,
        authorize: RouteGuard | Sequence[RouteGuard] | None = None,
    ) -> Callable[[Callable[..., Awaitable[Any] | Any]], Callable[..., Awaitable[Any] | Any]]:
        return self.route(path, methods=("GET",), name=name, authorize=authorize)

    def websocket(
        self,
        path: str,
        *,
        name: str | None = None,
        authorize: RouteGuard | Sequence[RouteGuard] | None = None,
    ) -> Callable[[Callable[..., Awaitable[Any] | Any]], Callable[..., Awaitable[Any] | Any]]:
        return self.route(path, methods=("WEBSOCKET",), name=name, authorize=authorize)

    def chatops_command(
        self,
        command: ChatOpsSlashCommand,
        *,
        name: str | None = None,
    ) -> Callable[[Callable[..., Awaitable[Any] | Any]], Callable[..., Awaitable[Any] | Any]]:
        """Register a ChatOps command handler bound to ``command``."""

        def decorator(func: Callable[..., Awaitable[Any] | Any]) -> Callable[..., Awaitable[Any] | Any]:
            binding = ChatOpsCommandBinding(
                command=command,
                handler=func,
                name=name or command.name,
            )
            self.chatops_commands.register(binding)
            return func

        return decorator

    def mount_static(
        self,
        path: str,
        *,
        directory: str | os.PathLike[str],
        name: str | None = None,
        index_file: str | None = "index.html",
        cache_control: str | None = "public, max-age=3600",
        follow_symlinks: bool = False,
        content_types: Mapping[str, str] | None = None,
    ) -> None:
        """Serve files rooted at ``directory`` under ``path``."""

        normalized = path.strip()
        if not normalized:
            raise ValueError("Static mount path cannot be empty")
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        stripped = normalized.strip("/")
        if not stripped:
            raise ValueError("Static mount path cannot be '/' or whitespace only")
        mount_path = "/" + stripped
        server = StaticFiles(
            directory=directory,
            executor=self.executor,
            index_file=index_file,
            follow_symlinks=follow_symlinks,
            cache_control=cache_control,
            content_types=content_types,
        )

        async def _serve_root(request: Request) -> Response:
            return await server.serve("", method=request.method, headers=request.headers)

        async def _serve_path(filepath: str, request: Request) -> Response:
            return await server.serve(filepath, method=request.method, headers=request.headers)

        self.router.add_route(mount_path, methods=("GET", "HEAD"), endpoint=_serve_root, name=name)
        self.router.add_route(f"{mount_path}/{{filepath:path}}", methods=("GET", "HEAD"), endpoint=_serve_path)
        if name is not None:
            self._named_routes[name] = mount_path

    def mount_asgi(
        self,
        path: str,
        app: ASGIApp,
        *,
        name: str | None = None,
        methods: Sequence[str] | None = None,
        startup: Callable[[], Awaitable[None] | None] | None = None,
        shutdown: Callable[[], Awaitable[None] | None] | None = None,
    ) -> None:
        """Mount an ASGI application under ``path``."""

        mount_path = _normalize_mount_prefix(path)
        proxy = _ASGIProxy(app, root_path=mount_path)
        route_methods = tuple(dict.fromkeys(methods or _ALL_HTTP_METHODS))

        if startup is not None:
            self.on_startup(startup)
        if shutdown is not None:
            self.on_shutdown(shutdown)

        async def _serve_root(request: Request) -> Response:
            scope_path = _resolve_mounted_scope_path(request.path, mount_path)
            return await proxy.dispatch(request, scope_path)

        async def _serve_path(remaining: str, request: Request) -> Response:
            suffix = "/" if not remaining else f"/{remaining}"
            return await proxy.dispatch(request, suffix)

        self.router.add_route(mount_path, methods=route_methods, endpoint=_serve_root, name=name)
        pattern = f"{mount_path}/{{remaining:path}}" if mount_path != "/" else "/{remaining:path}"
        self.router.add_route(pattern, methods=route_methods, endpoint=_serve_path)
        if name is not None:
            self._named_routes[name] = mount_path

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
        if middleware is security_headers_middleware:
            if middleware not in self._middlewares:
                self._middlewares.append(middleware)
            return
        if self._middlewares and self._middlewares[-1] is security_headers_middleware:
            self._middlewares.insert(len(self._middlewares) - 1, middleware)
        else:
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
        body_loader: Callable[[], Awaitable[bytes]] | None = None,
    ) -> Response:
        if "?" in path:
            path, extra = path.split("?", 1)
            if query_string:
                query_string = f"{query_string}&{extra}"
            else:
                query_string = extra
        tenant = self.tenant_resolver.resolve(host)
        try:
            match = self.router.find(method, path)
        except LookupError:
            request = Request(
                method=method,
                path=path,
                headers=headers or {},
                tenant=tenant,
                path_params={},
                query_string=query_string or "",
                body=body if body is not None else None,
                body_loader=None if body is not None else body_loader,
            )
            observation = self.observability.on_request_start(request)
            error = HTTPError(Status.NOT_FOUND, {"detail": "route_not_found"})
            response = exception_to_response(error)
            return self.observability.on_request_success(observation, response)
        request = Request(
            method=method,
            path=path,
            headers=headers or {},
            tenant=tenant,
            path_params=match.params,
            query_string=query_string or "",
            body=body if body is not None else None,
            body_loader=None if body is not None else body_loader,
        )
        scope = self.dependencies.scope(request)

        async def endpoint_handler(req: Request) -> Response:
            return await self._execute_route(match.route, req, scope)

        async def _execute_with_observability() -> Response:
            observation = self.observability.on_request_start(request)
            handler = apply_middleware(
                self._middlewares,
                endpoint_handler,
                observability=self.observability,
                request_context=observation,
            )
            try:
                response = await handler(request)
            except HTTPError as exc:
                response = exception_to_response(exc)
                response = self.observability.on_request_success(observation, response)
                return response
            except Exception as exc:
                status = getattr(exc, "status", None)
                if isinstance(status, Status):
                    status_code = int(status)
                elif isinstance(status, int):
                    status_code = status
                else:
                    status_code = int(Status.INTERNAL_SERVER_ERROR)
                self.observability.on_request_error(observation, exc, status_code=status_code)
                raise
            else:
                response = self.observability.on_request_success(observation, response)
                return response

        def _actor_from_principal(principal: CedarEntity | None) -> AuditActor | None:
            if principal is None:
                return None
            return AuditActor(
                id=principal.id,
                type=principal.type,
                attributes=dict(principal.attributes or {}),
            )

        if self.audit_trail:
            async with audit_context(tenant=request.tenant, actor=_actor_from_principal(request.principal)):
                return await _execute_with_observability()
        return await _execute_with_observability()

    async def _execute_route(self, route, request: Request, scope) -> Response:
        await self._authorize_route(route, request, scope)
        call_args: Dict[str, Any] = {}
        event_streams: list[EventStream] = []
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
            if annotation is EventStream:
                stream = EventStream(executor=self.executor)
                call_args[name] = stream
                event_streams.append(stream)
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
                    raise HTTPError(
                        Status.INTERNAL_SERVER_ERROR,
                        {"dependency": repr(annotation), "detail": str(exc)},
                    )
        result = route.spec.endpoint(**call_args)
        if inspect.isawaitable(result):
            result = await result
        if result is None and event_streams:
            if len(event_streams) > 1:
                raise RuntimeError("Multiple EventStream parameters require explicit return value")
            result = event_streams[0]
        return _coerce_response(result)

    async def _execute_websocket_route(self, route, websocket: WebSocket, scope) -> None:
        call_args: Dict[str, Any] = {}
        for name, parameter in route.signature.parameters.items():
            annotation = route.type_hints.get(name, parameter.annotation)
            if annotation is inspect.Signature.empty:
                annotation = str if name in route.param_names else Any
            if annotation is WebSocket:
                call_args[name] = websocket
                continue
            if annotation is Request:
                call_args[name] = websocket.request
                continue
            if annotation is TenantContext:
                call_args[name] = websocket.request.tenant
                continue
            if name in route.param_names:
                value = websocket.request.path_params[name]
                if annotation is str or annotation is Any:
                    call_args[name] = value
                else:
                    call_args[name] = convert_primitive(value, annotation, source=name)
                continue
            try:
                call_args[name] = await scope.get(annotation)
            except LookupError as exc:
                raise HTTPError(
                    Status.INTERNAL_SERVER_ERROR,
                    {"dependency": repr(annotation), "detail": str(exc)},
                ) from exc
        result = route.spec.endpoint(**call_args)
        if inspect.isawaitable(result):
            result = await result
        if result not in (None, websocket):
            raise RuntimeError("WebSocket handlers must not return a value")

    async def _authorize_route(self, route, request: Request, scope) -> None:
        if not route.guards:
            return
        principal = request.principal
        if principal is None:
            raise HTTPError(Status.FORBIDDEN, {"detail": "authentication_required"})
        try:
            engine = await scope.get(CedarEngine)
        except LookupError as exc:  # pragma: no cover - dependency misconfiguration
            raise HTTPError(Status.INTERNAL_SERVER_ERROR, {"detail": "authorization engine missing"}) from exc
        for guard in route.guards:
            if guard.principal_type not in ("*", principal.type):
                raise HTTPError(
                    Status.FORBIDDEN,
                    {"detail": "principal_not_allowed", "required": guard.principal_type},
                )
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
                    Status.FORBIDDEN,
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
        scope_type = scope.get("type")
        if scope_type == "http":
            await self._handle_http(scope, receive, send)
            return
        if scope_type == "websocket":
            await self._handle_websocket(scope, receive, send)
            return
        raise RuntimeError("MereApp only supports HTTP and WebSocket scopes")

    async def _handle_http(
        self,
        scope: Mapping[str, Any],
        receive: Callable[[], Awaitable[Mapping[str, Any]]],
        send: Callable[[Mapping[str, Any]], Awaitable[None]],
    ) -> None:
        headers, header_errors = self._decode_scope_headers(scope.get("headers", []))

        async def send_http_error(error: HTTPError) -> None:
            response = exception_to_response(error)
            await send(
                {
                    "type": "http.response.start",
                    "status": response.status,
                    "headers": [(name.encode("latin-1"), value.encode("latin-1")) for name, value in response.headers],
                }
            )
            await _send_response_body(response, send)

        if header_errors:
            error = HTTPError(Status.BAD_REQUEST, {"detail": "invalid_header_encoding"})
            await send_http_error(error)
            return
        host = headers.get("host")
        if not host:
            error = HTTPError(Status.BAD_REQUEST, {"detail": "missing_host_header"})
            await send_http_error(error)
            return
        max_body_bytes = self.config.max_request_body_bytes
        if max_body_bytes is not None:
            content_length = headers.get("content-length")
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    error = HTTPError(Status.BAD_REQUEST, {"detail": "invalid_content_length"})
                    await send_http_error(error)
                    return
                if declared_length < 0:
                    error = HTTPError(Status.BAD_REQUEST, {"detail": "invalid_content_length"})
                    await send_http_error(error)
                    return
                if declared_length > max_body_bytes:
                    error = HTTPError(
                        Status.PAYLOAD_TOO_LARGE,
                        {"detail": "request_body_too_large"},
                    )
                    await send_http_error(error)
                    return
        body_state: dict[str, Any] = {
            "buffer": bytearray(),
            "cached": None,
            "done": False,
        }
        query_string = self._decode_query_string(scope.get("query_string"))

        async def load_body() -> bytes:
            cached = body_state["cached"]
            if cached is not None:
                return cached
            while True:
                if body_state["done"]:
                    break
                message = await receive()
                message_type = message.get("type")
                if message_type == "http.disconnect":
                    body_state["done"] = True
                    continue
                if message_type != "http.request":
                    continue
                chunk = message.get("body", b"")
                if chunk:
                    chunk_bytes = bytes(chunk)
                    if max_body_bytes is not None:
                        projected = len(body_state["buffer"]) + len(chunk_bytes)
                        if projected > max_body_bytes:
                            body_state["done"] = True
                            body_state["cached"] = None
                            body_state["buffer"] = bytearray()
                            raise HTTPError(
                                Status.PAYLOAD_TOO_LARGE,
                                {"detail": "request_body_too_large"},
                            )
                    body_state["buffer"].extend(chunk_bytes)
                if not message.get("more_body", False):
                    body_state["done"] = True
                    continue
            body_bytes = bytes(body_state["buffer"])
            body_state["cached"] = body_bytes
            body_state["buffer"] = bytearray()
            return body_bytes

        try:
            response = await self.dispatch(
                scope["method"],
                scope["path"],
                host=host,
                query_string=query_string,
                headers=headers,
                body_loader=load_body,
            )
        except TenantResolutionError:
            error = HTTPError(Status.BAD_REQUEST, {"detail": "invalid_host_header"})
            response = exception_to_response(error)
        await send(
            {
                "type": "http.response.start",
                "status": response.status,
                "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in response.headers],
            }
        )
        await _send_response_body(response, send)

    async def _handle_websocket(
        self,
        scope: Mapping[str, Any],
        receive: Callable[[], Awaitable[Mapping[str, Any]]],
        send: Callable[[Mapping[str, Any]], Awaitable[None]],
    ) -> None:
        headers, header_errors = self._decode_scope_headers(scope.get("headers", []))
        if header_errors:
            await send({"type": "websocket.close", "code": 4400})
            return
        host = headers.get("host")
        if not host:
            await send({"type": "websocket.close", "code": 4400})
            return
        if not self._is_allowed_websocket_origin(host, headers, scope):
            await send({"type": "websocket.close", "code": 4403})
            return
        try:
            tenant = self.tenant_resolver.resolve(host)
        except (LookupError, TenantResolutionError):
            await send({"type": "websocket.close", "code": 4404})
            return
        path = scope.get("path", "")
        try:
            match = self.router.find("WEBSOCKET", path)
        except LookupError:
            await send({"type": "websocket.close", "code": 4404})
            return
        request = Request(
            method="WEBSOCKET",
            path=path,
            headers=headers,
            tenant=tenant,
            path_params=match.params,
            query_string=self._decode_query_string(scope.get("query_string")),
        )
        scope_obj = self.dependencies.scope(request)
        websocket = WebSocket(
            scope=scope,
            receive=receive,
            send=send,
            request=request,
            executor=self.executor,
        )
        try:
            initial = await receive()
        except Exception:
            await websocket.close(code=1011)
            raise
        message_type = initial.get("type")
        if message_type == "websocket.disconnect":
            return
        if message_type != "websocket.connect":
            await websocket.close(code=4400)
            return
        try:
            await self._authorize_route(match.route, request, scope_obj)
        except HTTPError as exc:
            await websocket.close(code=_status_to_websocket_close(exc.status))
            return
        try:
            await self._execute_websocket_route(match.route, websocket, scope_obj)
        except HTTPError as exc:
            await websocket.close(code=_status_to_websocket_close(exc.status))
        except WebSocketDisconnect:
            pass
        except Exception:
            await websocket.close(code=1011)
            raise
        finally:
            await websocket.join_background()
            if not websocket.closed:
                await websocket.close()

    @staticmethod
    def _decode_scope_headers(raw_headers: Iterable[tuple[HeaderPart, HeaderPart]]) -> tuple[dict[str, str], bool]:
        decoded: dict[str, str] = {}
        had_errors = False
        for raw_name, raw_value in raw_headers:
            name, name_error = _decode_header_component(raw_name)
            value, value_error = _decode_header_component(raw_value)
            had_errors = had_errors or name_error or value_error
            if not name:
                continue
            decoded[name.lower()] = value
        return decoded, had_errors

    def _is_allowed_websocket_origin(
        self,
        host: str,
        headers: Mapping[str, str],
        scope: Mapping[str, Any],
    ) -> bool:
        websocket_scheme = str(scope.get("scheme") or "").lower()
        allowed_origin_schemes = {"http", "https"}
        if websocket_scheme in {"ws", "wss"}:
            allowed_origin_schemes = {"https"} if websocket_scheme == "wss" else {"http"}

        origin_value = headers.get("origin") or headers.get("sec-websocket-origin")
        if origin_value is None:
            return False
        origin_scheme, origin_host, origin_port = _parse_origin_host(origin_value, require_http_scheme=True)
        if origin_scheme is None or origin_host is None:
            return False
        if origin_scheme not in allowed_origin_schemes:
            return False

        _, expected_host, expected_port = _parse_origin_host(host, require_http_scheme=False)
        if expected_host is None:
            return False

        allowed_entries: list[tuple[str, int | None, set[int]]] = []
        host_defaults = _default_ports_for_scheme(websocket_scheme)
        allowed_entries.append((expected_host, expected_port, host_defaults))
        if expected_port is None:
            for default_port in host_defaults:
                allowed_entries.append((expected_host, default_port, host_defaults))

        for entry in self.config.websocket_trusted_origins:
            entry_scheme, entry_host, entry_port = _parse_origin_host(entry, require_http_scheme=False)
            if entry_host is None:
                continue
            defaults = _default_ports_for_scheme(entry_scheme)
            allowed_entries.append((entry_host, entry_port, defaults))
            if entry_port is None:
                for default_port in defaults:
                    allowed_entries.append((entry_host, default_port, defaults))

        origin_defaults = _default_ports_for_scheme(origin_scheme)
        for allowed_host, allowed_port, allowed_defaults in allowed_entries:
            if origin_host != allowed_host:
                continue
            if origin_port == allowed_port:
                return True
            if origin_port is None and allowed_port in origin_defaults:
                return True
            if allowed_port is None and origin_port in allowed_defaults:
                return True
        return False

    @staticmethod
    def _decode_query_string(raw: object | None) -> str:
        if raw is None:
            return ""
        if isinstance(raw, str):
            return raw
        if isinstance(raw, (bytes, bytearray, memoryview)):
            return bytes(raw).decode("latin-1")
        return str(raw)  # pragma: no cover - defensive fallback


class Mere(MereApp):
    """Convenience subclass exposing configuration helpers."""

    @classmethod
    def from_config(cls, config: AppConfig | Mapping[str, Any]) -> "Mere":
        if isinstance(config, AppConfig):
            return cls(config=config)
        return cls(config=msgspec.convert(config, type=AppConfig))


class _ASGIProxy:
    __slots__ = ("_app", "_root_path")

    def __init__(self, app: ASGIApp, *, root_path: str) -> None:
        self._app = app
        self._root_path = "" if root_path == "/" else root_path

    async def dispatch(self, request: Request, scope_path: str) -> Response:
        return await _call_asgi_app(
            self._app,
            request,
            scope_path,
            root_path=self._root_path,
        )


def _normalize_mount_prefix(path: str) -> str:
    normalized = path.strip()
    if not normalized:
        raise ValueError("ASGI mount path cannot be empty")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if normalized != "/":
        normalized = normalized.rstrip("/")
    return normalized or "/"


def _resolve_mounted_scope_path(full_path: str, mount_path: str) -> str:
    if mount_path == "/":
        target = full_path
    else:
        target = full_path[len(mount_path) :]
    if not target:
        return "/"
    return target if target.startswith("/") else "/" + target


async def _call_asgi_app(
    asgi_app: ASGIApp,
    request: Request,
    scope_path: str,
    *,
    root_path: str,
) -> Response:
    path = scope_path or "/"
    body = await request.body()
    request_sent = False

    async def receive() -> Mapping[str, Any]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    status_code: int | None = None
    headers: list[tuple[str, str]] = []
    payload = bytearray()

    async def send(message: Mapping[str, Any]) -> None:
        nonlocal status_code, headers
        message_type = message.get("type")
        if message_type == "http.response.start":
            status_code = int(message.get("status", int(Status.OK)))
            raw_headers = message.get("headers") or []
            decoded: list[tuple[str, str]] = []
            for name, value in raw_headers:
                decoded.append((_decode_asgi_component(name), _decode_asgi_component(value)))
            headers = decoded
        elif message_type == "http.response.body":
            chunk = message.get("body", b"") or b""
            if chunk:
                payload.extend(bytes(chunk))

    scope_headers = [(key.encode("latin-1"), value.encode("latin-1")) for key, value in request.headers.items()]
    if root_path:
        normalized_root = root_path.rstrip("/") or "/"
        if path == "/":
            full_path = normalized_root
        else:
            full_path = normalized_root + path
    else:
        full_path = path
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": request.method,
        "scheme": request.header("x-forwarded-proto", "https"),
        "path": full_path,
        "raw_path": full_path.encode("latin-1", errors="ignore"),
        "root_path": root_path,
        "query_string": request.raw_query.encode("latin-1", errors="ignore"),
        "headers": scope_headers,
        "client": None,
        "server": None,
        "state": {},
    }
    await asgi_app(scope, receive, send)
    if status_code is None:
        raise RuntimeError("Mounted ASGI application did not send a response start message")
    return Response(status=status_code, headers=tuple(headers), body=bytes(payload))


def _decode_asgi_component(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("latin-1", errors="ignore")
    return str(value)


def _decode_header_component(component: object) -> tuple[str, bool]:
    if isinstance(component, str):
        return component, False
    if isinstance(component, (bytes, bytearray, memoryview)):
        raw = bytes(component)
        try:
            return raw.decode("latin-1"), False
        except UnicodeDecodeError:  # pragma: no cover - latin-1 decoding should not fail
            return raw.decode("latin-1", errors="replace"), True
    return str(component), True


def _parse_origin_host(value: str, *, require_http_scheme: bool) -> tuple[str | None, str | None, int | None]:
    candidate = value.strip()
    if not candidate:
        return None, None, None
    target = candidate if "://" in candidate else f"//{candidate}"
    try:
        parts = urlsplit(target, allow_fragments=False)
    except ValueError:
        return None, None, None
    scheme = parts.scheme.lower() if parts.scheme else None
    if require_http_scheme and scheme not in {"http", "https"}:
        return None, None, None
    host = parts.hostname
    try:
        port = parts.port
    except ValueError:
        return None, None, None
    if host is None:
        return None, None, None
    return scheme, host.lower(), port


def _default_ports_for_scheme(scheme: str | None) -> set[int]:
    normalized = (scheme or "").lower()
    if normalized in {"https", "wss"}:
        return {443}
    if normalized in {"http", "ws"}:
        return {80}
    return {80, 443}


def _is_struct(annotation: Any) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, msgspec.Struct)


async def _send_response_body(
    response: Response,
    send: Callable[[Mapping[str, Any]], Awaitable[None]],
) -> None:
    stream = response.stream
    if stream is None:
        await send({"type": "http.response.body", "body": response.body})
        return
    iterator = _ensure_async_iterator(stream)
    try:
        chunk = await anext(iterator)
    except StopAsyncIteration:
        await send({"type": "http.response.body", "body": response.body, "more_body": False})
        return
    await send({"type": "http.response.body", "body": chunk, "more_body": True})
    async for chunk in iterator:
        await send({"type": "http.response.body", "body": chunk, "more_body": True})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


def _ensure_async_iterator(stream: AsyncIterable[bytes]) -> AsyncIterator[bytes]:
    if isinstance(stream, AsyncIterator):
        return stream
    return stream.__aiter__()


def _status_to_websocket_close(status: int | Status) -> int:
    code = int(status)
    mapping = {
        400: 4400,
        401: 4401,
        403: 4403,
        404: 4404,
    }
    if code in mapping:
        return mapping[code]
    if 400 <= code < 500:
        return 4400
    if 500 <= code < 600:
        return 1011
    return 1008


def _coerce_response(result: Any) -> Response:
    if isinstance(result, Response):
        return result
    if isinstance(result, EventStream):
        return result.to_response()
    if result is None:
        return apply_default_security_headers(Response(status=int(Status.NO_CONTENT), body=b""))
    if isinstance(result, str):
        return PlainTextResponse(result)
    return JSONResponse(result)
