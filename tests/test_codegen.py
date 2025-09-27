from __future__ import annotations

from typing import Any

import artemis.codegen as ts_codegen
from artemis.codegen import generate_typescript_client


def _build_spec() -> dict[str, Any]:
    return {
        "components": {
            "schemas": {
                "Widget": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "flags": {"type": "array", "items": {"type": "boolean"}},
                    },
                    "required": ["id"],
                    "additionalProperties": {"type": "integer"},
                },
                "OnlyEnum": {"enum": ["alpha", "beta", 3]},
                "MaybeNumber": {"anyOf": [{"type": "number"}, {"type": "null"}]},
                "LiteralValue": {"const": {"kind": "literal"}},
                "MultiType": {"type": ["string", "null"]},
                "Dictionary": {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/components/schemas/Widget"},
                },
                "UnknownType": {"type": "mystery"},
            }
        },
        "paths": {
            "/items/{id}": {
                "get": {
                    "operationId": "123 fetch item!",
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "integer"}},
                    ],
                    "responses": {
                        "200": {
                            "description": "Item text",
                            "content": {"text/plain": {"schema": {"type": "string"}}},
                        }
                    },
                }
            },
            "/items": {
                "post": {
                    "operationId": "create item",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"name": {"type": "string"}},
                                    "required": ["name"],
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Created",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Widget"}}},
                        }
                    },
                }
            },
            "/noop": {
                "delete": {
                    "operationId": "noop",
                    "responses": {"204": {"description": "No Content"}},
                }
            },
            "/other": {
                "patch": {
                    "operationId": "!special-case!",
                    "requestBody": {"content": {"application/x-custom": {"schema": {"type": "string"}}}},
                    "responses": {
                        "202": {
                            "description": "Accepted",
                            "content": {},
                        }
                    },
                }
            },
        },
    }


def test_generate_typescript_client_emits_strict_types() -> None:
    spec = _build_spec()
    source = generate_typescript_client(spec)
    assert "export interface Widget {" in source
    assert 'export type OnlyEnum = "alpha" | "beta" | 3;' in source
    assert "export type MaybeNumber = number | null;" in source
    assert 'export type LiteralValue = {"kind": "literal"};' in source
    assert "export type MultiType = string | null;" in source
    assert "export interface Dictionary {" in source
    assert "export type UnknownType = unknown;" in source
    assert "export interface ItemsIdGetInput {" in source
    assert "export type ItemsIdGetOutput = string;" in source
    assert "const op_123FetchItemRoute = createRoute<ItemsIdGetInput, ItemsIdGetOutput>({" in source
    assert "async op_123FetchItem(input: ItemsIdGetInput): Promise<ItemsIdGetOutput> {" in source
    assert "op_123FetchItemSuspense(input: ItemsIdGetInput): SuspenseResource<ItemsIdGetOutput> {" in source
    assert "op_123FetchItemLoadable(input: ItemsIdGetInput): Loadable<ItemsIdGetOutput> {" in source
    assert "op_123FetchItemQuery(" in source
    assert "export type ItemsPostOutput = Widget;" in source
    assert "const createItemRoute = createRoute<ItemsPostInput, ItemsPostOutput>({" in source
    assert "createItemSuspense(input: ItemsPostInput): SuspenseResource<ItemsPostOutput> {" in source
    assert "createItemQuery(" in source
    assert "const noopRoute = createRoute<NoopDeleteInput, NoopDeleteOutput>({" in source
    assert "export type NoopDeleteOutput = void;" in source
    assert "const specialCaseRoute = createRoute<OtherPatchInput, OtherPatchOutput>({" in source
    assert "export const routes = {" in source
    assert "  op_123FetchItem: op_123FetchItemRoute," in source
    assert "mediaType: 'application/json'" in source
    assert "mediaType: 'application/x-custom'" in source


def test_generate_client_without_components() -> None:
    spec: dict[str, Any] = {
        "paths": {
            "/ping": {
                "get": {
                    "operationId": "ping",
                    "responses": {"200": {"description": "OK"}},
                }
            }
        }
    }
    source = generate_typescript_client(spec)
    assert "export class ArtemisClient" in source
    assert "async ping(input: PingGetInput): Promise<PingGetOutput> {" in source
    assert "pingSuspense(input: PingGetInput): SuspenseResource<PingGetOutput> {" in source


def test_generate_client_without_paths() -> None:
    source = generate_typescript_client({})
    assert "export const routes = {" not in source
    assert " = createRoute<" not in source


def test_schema_renderer_handles_combinations() -> None:
    renderer = ts_codegen._SchemaRenderer(_build_spec()["components"]["schemas"])
    assert renderer.render_type({"$ref": "#/components/schemas/Widget"}) == "Widget"
    assert renderer.render_type({"enum": ["one", 2]}) == '"one" | 2'
    assert renderer.render_type({"const": True}) == "true"
    assert renderer.render_type({"type": ["string", "null"]}) == "string | null"
    assert renderer.render_type({"type": "array", "items": {"type": "integer"}}) == "Array<number>"
    assert renderer.render_type({"type": "boolean"}) == "boolean"
    assert renderer.render_type({"type": "null"}) == "null"
    object_type = renderer.render_type(
        {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": {"type": "integer"},
        }
    )
    assert "[key: string]: number;" in object_type
    assert renderer.render_type({"type": "mystery"}) == "unknown"


def test_operation_helpers_cover_edge_cases() -> None:
    assert ts_codegen._sanitize_operation_id("!!!") == "operation"
    assert ts_codegen._sanitize_operation_id("123") == "op_123"
    assert ts_codegen._type_name_from_path("/", "GET") == "RootGet"
    assert ts_codegen._type_name_from_path("/123/resource", "POST") == "Route123ResourcePost"
    request_body = ts_codegen._select_request_body(
        {
            "requestBody": {
                "content": {
                    "application/json": {"schema": {"type": "object"}},
                    "text/plain": {"schema": {"type": "string"}},
                }
            }
        }
    )
    assert request_body == ("application/json", {"type": "object"})
    fallback_body = ts_codegen._select_request_body(
        {"requestBody": {"content": {"text/plain": {"schema": {"type": "string"}}}}}
    )
    assert fallback_body == ("text/plain", {"type": "string"})
    assert ts_codegen._select_request_body({"requestBody": {"content": {}}}) is None
    assert ts_codegen._select_request_body({}) is None

    assert ts_codegen._select_response({"responses": {"200": {"description": "OK"}}}) == (
        "200",
        {"description": "OK"},
    )
    assert ts_codegen._select_response({"responses": {"202": {"description": "Accepted"}}}) == (
        "202",
        {"description": "Accepted"},
    )
    assert ts_codegen._select_response({"responses": {"400": {"description": "Bad"}}}) == (
        "200",
        {"description": "Success"},
    )
