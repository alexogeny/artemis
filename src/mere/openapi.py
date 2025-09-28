"""Generate OpenAPI specifications from Mere route metadata."""

from __future__ import annotations

import inspect
from collections import defaultdict
from collections.abc import Awaitable as CBAwaitable
from typing import Any, Literal, Mapping, Sequence, Union, get_args, get_origin

import msgspec
from msgspec import structs

from .application import MereApp
from .responses import Response
from .routing import Route


def generate_openapi(app: MereApp, *, title: str | None = None, version: str = "1.0.0") -> dict[str, Any]:
    """Return an OpenAPI 3.1 specification for ``app``."""

    registry = _SchemaRegistry()
    paths: dict[str, dict[str, Any]] = defaultdict(dict)
    for route in sorted(app.router._routes, key=lambda item: item.spec.path):
        for method in route.spec.methods:
            operation = _operation_from_route(route, method, registry)
            paths[route.spec.path][method.lower()] = operation

    spec: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {
            "title": title or f"{app.config.site.title()} API",
            "version": version,
        },
        "servers": [
            {
                "url": "https://{tenant}.{site}.{domain}",
                "variables": {
                    "tenant": {"default": app.config.marketing_tenant},
                    "site": {"default": app.config.site},
                    "domain": {"default": app.config.domain},
                },
            }
        ],
        "paths": dict(paths),
    }
    if registry.components:
        spec["components"] = {"schemas": dict(sorted(registry.components.items()))}
    return spec


def _operation_from_route(route: Route, method: str, registry: "_SchemaRegistry") -> dict[str, Any]:
    operation_id = route.spec.name or f"{method.lower()}_{route.spec.endpoint.__name__}"
    docstring = inspect.getdoc(route.spec.endpoint) or ""
    summary = docstring.splitlines()[0] if docstring else None
    operation: dict[str, Any] = {
        "operationId": operation_id,
    }
    if summary:
        operation["summary"] = summary
    parameters = _path_parameters(route, registry)
    if parameters:
        operation["parameters"] = parameters
    request_body = _request_body(route, registry)
    if request_body is not None:
        operation["requestBody"] = request_body
    operation["responses"] = _responses(route, registry)
    if route.guards:
        operation["x-mere-guards"] = [
            {
                "action": guard.action,
                "resource_type": guard.resource_type,
                "principal_type": guard.principal_type,
                "resource_id": guard.resource_id if isinstance(guard.resource_id, str) else None,
            }
            for guard in route.guards
        ]
    return operation


def _path_parameters(route: Route, registry: "_SchemaRegistry") -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for name in route.param_names:
        annotation = route.type_hints.get(name, str)
        schema = registry.schema_for(annotation)
        parameters.append(
            {
                "name": name,
                "in": "path",
                "required": True,
                "schema": schema,
            }
        )
    return parameters


def _request_body(route: Route, registry: "_SchemaRegistry") -> dict[str, Any] | None:
    fields: list[tuple[str, Any]] = []
    for name, parameter in route.signature.parameters.items():
        if name in route.param_names:
            continue
        annotation = route.type_hints.get(name, parameter.annotation)
        annotation = registry._unwrap(annotation)
        if annotation is inspect.Signature.empty:
            continue
        if annotation is route.type_hints.get("return"):
            continue
        if registry.is_struct(annotation):
            fields.append((name, annotation))
    if not fields:
        return None
    if len(fields) == 1:
        _, annotation = fields[0]
        schema = registry.schema_for(annotation)
    else:
        schema = {
            "type": "object",
            "properties": {},
        }
        for name, annotation in fields:
            schema["properties"][name] = registry.schema_for(annotation)
        schema["required"] = [name for name, _ in fields]
    content_type = "application/json"
    return {"content": {content_type: {"schema": schema}}}


def _responses(route: Route, registry: "_SchemaRegistry") -> dict[str, Any]:
    annotation = route.type_hints.get("return", Any)
    annotation = registry._unwrap(annotation)
    origin = get_origin(annotation)
    if origin is CBAwaitable:
        args = get_args(annotation)
        annotation = registry._unwrap(args[0]) if args else Any
    if annotation is inspect.Signature.empty or annotation is None or annotation is type(None):
        return {"204": {"description": "No Content"}}
    if registry.is_response(annotation):
        return {"200": {"description": "Response"}}
    media_type = "application/json"
    if annotation is str:
        media_type = "text/plain"
        schema = {"type": "string"}
    else:
        schema = registry.schema_for(annotation)
    return {
        "200": {
            "description": "Success",
            "content": {
                media_type: {
                    "schema": schema,
                }
            },
        }
    }


class _SchemaRegistry:
    def __init__(self) -> None:
        self.components: dict[str, Any] = {}
        self._in_progress: set[type[Any]] = set()

    @staticmethod
    def _unwrap(annotation: Any) -> Any:
        origin = get_origin(annotation)
        if origin is None:
            return annotation
        if getattr(origin, "__qualname__", "") == "Annotated":
            return _SchemaRegistry._unwrap(get_args(annotation)[0])
        return annotation

    @staticmethod
    def is_struct(annotation: Any) -> bool:
        return isinstance(annotation, type) and issubclass(annotation, msgspec.Struct)

    @staticmethod
    def is_response(annotation: Any) -> bool:
        return inspect.isclass(annotation) and issubclass(annotation, Response)

    def schema_for(self, annotation: Any) -> dict[str, Any]:
        annotation = self._unwrap(annotation)
        origin = get_origin(annotation)
        if origin is None:
            return self._schema_for_concrete(annotation)
        if origin in (list, tuple, set, Sequence):
            item_type = get_args(annotation)[0] if get_args(annotation) else Any
            return {"type": "array", "items": self.schema_for(item_type)}
        if origin in (dict, Mapping):
            args = get_args(annotation)
            value_type = args[1] if len(args) == 2 else Any
            return {"type": "object", "additionalProperties": self.schema_for(value_type)}
        if origin is Union:
            schemas = []
            for arg in get_args(annotation):
                if arg is type(None):
                    schemas.append({"type": "null"})
                else:
                    schemas.append(self.schema_for(arg))
            return {"anyOf": schemas}
        if origin is Literal:
            return {"enum": list(get_args(annotation))}
        return {"type": "object"}

    def _schema_for_concrete(self, annotation: Any) -> dict[str, Any]:
        if annotation in (Any, object):
            return {"type": "object"}
        if annotation in (str,):
            return {"type": "string"}
        if annotation in (int,):
            return {"type": "integer"}
        if annotation in (float,):
            return {"type": "number"}
        if annotation in (bool,):
            return {"type": "boolean"}
        if annotation is bytes:
            return {"type": "string", "format": "byte"}
        if annotation is type(None):
            return {"type": "null"}
        if self.is_struct(annotation):
            return self._register_struct(annotation)
        return {"type": "object"}

    def _register_struct(self, struct_type: type[msgspec.Struct]) -> dict[str, Any]:
        name = struct_type.__name__
        if name in self.components:
            return {"$ref": f"#/components/schemas/{name}"}
        if struct_type in self._in_progress:
            return {"$ref": f"#/components/schemas/{name}"}
        self._in_progress.add(struct_type)
        properties: dict[str, Any] = {}
        required: list[str] = []
        for field in structs.fields(struct_type):
            properties[field.name] = self.schema_for(field.type)
            if field.required:
                required.append(field.name)
        schema: dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        self.components[name] = schema
        self._in_progress.remove(struct_type)
        return {"$ref": f"#/components/schemas/{name}"}


__all__ = ["generate_openapi"]
