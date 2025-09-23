from __future__ import annotations

from collections.abc import Awaitable
from typing import Annotated, Literal, Optional, Protocol

import msgspec

import artemis.openapi as openapi_module
from artemis import AppConfig, ArtemisApp, JSONResponse, Observability, ObservabilityConfig, PlainTextResponse, Response
from artemis.openapi import generate_openapi
from artemis.routing import RouteGuard


class _ResponseLike(Protocol):
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class Payload(msgspec.Struct):
    identifier: int
    label: Annotated[str, "metadata"]
    data: bytes


class Extra(msgspec.Struct):
    enabled: bool = False


class Result(msgspec.Struct):
    value: int


class DocPayload(msgspec.Struct):
    value: float


class RecursiveNode(msgspec.Struct):
    child: Optional["RecursiveNode"] = None


def _make_app() -> ArtemisApp:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    config = AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",))
    app = ArtemisApp(config=config, observability=observability)

    guard = RouteGuard(action="read", resource_type="item", resource_id="42", principal_type="user")

    @app.post("/items/{item_id}", name="update_item")
    async def update_item(item_id: int, payload: Payload, extra: Extra) -> list[Result]:
        return [Result(value=item_id)]

    @app.get("/text")
    async def text() -> str:
        return "ok"

    @app.route("/void", methods=("DELETE",))
    async def void() -> None:
        return None

    @app.get("/raw", name="raw", authorize=guard)
    async def raw() -> Response:
        return JSONResponse({"status": "ok"})

    @app.get("/maybe")
    async def maybe() -> Optional[str]:
        return "maybe"

    @app.get("/plain")
    async def plain() -> _ResponseLike:
        return PlainTextResponse("pong")

    return app


def test_generate_openapi_captures_route_metadata() -> None:
    app = _make_app()
    spec = generate_openapi(app, title="Demo", version="2.0.0")

    info = spec["info"]
    assert info["title"] == "Demo"
    assert info["version"] == "2.0.0"

    update = spec["paths"]["/items/{item_id}"]["post"]
    assert update["operationId"] == "update_item"
    schema = update["requestBody"]["content"]["application/json"]["schema"]
    assert schema["type"] == "object"
    assert set(schema["required"]) == {"payload", "extra"}

    raw = spec["paths"]["/raw"]["get"]
    guards = raw["x-artemis-guards"]
    assert guards[0]["resource_type"] == "item"
    assert raw["responses"]["200"]["description"] == "Response"

    text = spec["paths"]["/text"]["get"]
    content = text["responses"]["200"]["content"]["text/plain"]
    assert content["schema"] == {"type": "string"}

    void = spec["paths"]["/void"]["delete"]
    assert void["responses"]["204"]["description"] == "No Content"

    maybe = spec["paths"]["/maybe"]["get"]
    any_of = maybe["responses"]["200"]["content"]["application/json"]["schema"]
    assert {item["type"] for item in any_of["anyOf"]} == {"string", "null"}

    components = spec["components"]["schemas"]
    assert set(components) >= {"Payload", "Extra", "Result"}
    assert components["Extra"]["properties"] == {"enabled": {"type": "boolean"}}


def test_generate_openapi_handles_docstrings_and_skips_parameters() -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    config = AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",))
    app = ArtemisApp(config=config, observability=observability)

    @app.post("/doc/{item_id}")
    async def documented(item_id: int, note, count: int, result: Result, payload: DocPayload) -> Result:
        """Documented endpoint."""

        return Result(value=item_id)

    @app.get("/awaitable")
    async def awaited() -> Awaitable[Result]:
        async def inner() -> Result:
            return Result(value=1)

        return inner()

    spec = generate_openapi(app, title="Doc API", version="1.0.0")
    operation = spec["paths"]["/doc/{item_id}"]["post"]
    assert operation["summary"] == "Documented endpoint."
    assert operation["parameters"][0]["name"] == "item_id"
    request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema == {"$ref": "#/components/schemas/DocPayload"}
    awaitable_response = spec["paths"]["/awaitable"]["get"]["responses"]["200"]
    assert awaitable_response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/Result"
    }


def test_generate_openapi_without_components() -> None:
    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False)
    )
    config = AppConfig(site="demo", domain="example.com", allowed_tenants=("acme",))
    app = ArtemisApp(config=config, observability=observability)

    @app.get("/ping")
    async def ping() -> str:
        return "pong"

    spec = generate_openapi(app)
    assert "components" not in spec


def test_schema_registry_covers_python_types() -> None:
    registry = openapi_module._SchemaRegistry()
    assert registry.schema_for(list[int]) == {"type": "array", "items": {"type": "integer"}}
    assert registry.schema_for(tuple[str]) == {"type": "array", "items": {"type": "string"}}
    assert registry.schema_for(dict[str, bytes]) == {
        "type": "object",
        "additionalProperties": {"type": "string", "format": "byte"},
    }
    assert registry.schema_for(Annotated[int, "ignored"]) == {"type": "integer"}
    assert registry.schema_for(Optional[str]) == {"anyOf": [{"type": "string"}, {"type": "null"}]}
    assert registry.schema_for(object) == {"type": "object"}
    assert registry.schema_for(float) == {"type": "number"}
    assert registry.schema_for(type(None)) == {"type": "null"}
    assert registry.schema_for(Literal["a", 1]) == {"enum": ["a", 1]}

    class Example(msgspec.Struct):
        name: str
        count: int

    ref = registry.schema_for(Example)
    assert ref == {"$ref": "#/components/schemas/Example"}
    assert "Example" in registry.components
    assert registry.schema_for(Example) == {"$ref": "#/components/schemas/Example"}

    assert registry.schema_for(RecursiveNode) == {"$ref": "#/components/schemas/RecursiveNode"}
    assert registry.schema_for(Response) == {"$ref": "#/components/schemas/Response"}
