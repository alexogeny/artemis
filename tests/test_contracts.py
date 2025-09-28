from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Protocol

import msgspec
import pytest

from mere import AppConfig, JSONResponse, MereApp, TestClient
from mere.codegen import generate_typescript_client
from mere.golden import GoldenFile, RequestResponseRecorder
from mere.observability import Observability, ObservabilityConfig
from mere.openapi import generate_openapi


class _ResponseLike(Protocol):
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class CreateItem(msgspec.Struct):
    name: str


def _build_app() -> MereApp:
    class _DeterministicIds:
        def __init__(self) -> None:
            self._counter = 0

        def __call__(self, size: int) -> str:
            self._counter += 1
            return f"{self._counter:0{size * 2}x}"

    observability = Observability(
        ObservabilityConfig(opentelemetry_enabled=False, datadog_enabled=False, sentry_enabled=False),
        id_generator=_DeterministicIds(),
    )
    app = MereApp(
        AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")),
        observability=observability,
    )

    @app.get("/items/{item_id}", name="get_item")
    async def read_item(item_id: int) -> dict[str, int | str]:
        return {"id": item_id, "name": f"Item {item_id}"}

    @app.post("/items", name="create_item")
    async def create_item(payload: CreateItem) -> _ResponseLike:
        return JSONResponse({"created": payload.name}, status=201)

    @app.get("/ping")
    async def ping() -> str:
        return "pong"

    return app


def _golden(path: str) -> GoldenFile:
    return GoldenFile(Path("tests/golden") / path)


def test_openapi_and_typescript_generation(tmp_path: Path) -> None:
    app = _build_app()
    spec = generate_openapi(app, title="Demo API", version="0.1.0")
    _golden("openapi.json").ensure(spec)

    client_source = generate_typescript_client(spec)
    _golden("client.ts").ensure(client_source)

    ts_path = tmp_path / "client.ts"
    ts_path.write_text(client_source)
    if shutil.which("npx") is None:
        pytest.skip("npx is not available")
    subprocess.run(
        [
            "npx",
            "--yes",
            "tsc",
            "--noEmit",
            "--strict",
            "--target",
            "ES2020",
            "--module",
            "ES2020",
            "--moduleResolution",
            "bundler",
            str(ts_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.asyncio
async def test_request_response_recording() -> None:
    recorder = RequestResponseRecorder(_golden("recordings.json"))
    app = _build_app()
    async with TestClient(app, recorder=recorder) as client:
        response = await client.get("/items/1", tenant="acme", label="fetch_item")
        assert response.status == 200
        await client.post("/items", tenant="acme", json={"name": "Sample"}, label="create_item")
    recorder.finalize()
