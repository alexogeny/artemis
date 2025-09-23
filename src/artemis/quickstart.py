"""Developer quickstart routes for OpenAPI, codegen, and health checks."""

from __future__ import annotations

import os
from typing import Final

from .application import ArtemisApp
from .codegen import generate_typescript_client
from .openapi import generate_openapi
from .responses import JSONResponse, Response

_DEV_ENVIRONMENTS: Final[set[str]] = {"development", "dev", "local", "test"}
_DEV_DOMAIN_SUFFIXES: Final[tuple[str, ...]] = (".local", ".localhost", ".test")
_DEV_DOMAINS: Final[set[str]] = {"localhost", "127.0.0.1"}


def attach_quickstart(
    app: ArtemisApp,
    *,
    base_path: str = "/__artemis",
    environment: str | None = None,
    allow_production: bool = False,
) -> None:
    """Attach development-only routes for OpenAPI, TypeScript clients, and ping health."""

    env = (environment or os.getenv("ARTEMIS_ENV") or "development").lower()
    domain = app.config.domain.lower()
    is_dev_env = env in _DEV_ENVIRONMENTS
    is_dev_domain = domain in _DEV_DOMAINS or any(domain.endswith(suffix) for suffix in _DEV_DOMAIN_SUFFIXES)
    if not allow_production and not (is_dev_env or is_dev_domain):
        raise RuntimeError("Quickstart routes are only available in development environments")

    normalized = base_path.strip()
    if not normalized:
        normalized = ""
    else:
        normalized = "/" + normalized.strip("/")

    ping_path = f"{normalized}/ping" if normalized else "/ping"
    openapi_path = f"{normalized}/openapi.json" if normalized else "/openapi.json"
    client_path = f"{normalized}/client.ts" if normalized else "/client.ts"

    @app.get(ping_path, name="quickstart_ping")
    async def quickstart_ping() -> str:
        return "pong"

    @app.get(openapi_path, name="quickstart_openapi")
    async def quickstart_openapi() -> Response:
        spec = generate_openapi(app)
        return JSONResponse(spec)

    @app.get(client_path, name="quickstart_client")
    async def quickstart_client() -> Response:
        spec = generate_openapi(app)
        source = generate_typescript_client(spec)
        return Response(
            headers=(("content-type", "application/typescript"),),
            body=source.encode("utf-8"),
        )


__all__ = ["attach_quickstart"]
