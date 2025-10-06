"""Minimal Mere application that ships with the framework.

Run ``uv sync`` once, then ``uv run example.py`` to boot a local Mere app with the
bootstrap bundle enabled. The server exposes the built-in authentication flows
under ``/__mere`` alongside a small JSON route at ``/`` that echoes the resolved
tenant.

By default the example expects tenant hosts like ``acme.demo.local.test`` and
``beta.demo.local.test``. Override ``MERE_SITE``, ``MERE_DOMAIN``, or
``MERE_ALLOWED_TENANTS`` to match your environment. Provide ``DATABASE_URL`` to
back the bootstrap with PostgreSQL; when omitted the demo operates in memory.
"""

from __future__ import annotations

import os
from typing import Iterable

from mere import AppConfig, MereApp
from mere.database import DatabaseConfig, PoolConfig
from mere.requests import Request
from mere.responses import JSONResponse, Response
from mere.server import ServerConfig, run


def _parse_allowed_tenants(raw: str | None) -> tuple[str, ...]:
    """Return a sorted tuple of tenant slugs for the bootstrap resolver."""

    if not raw:
        return ("acme", "beta")
    candidates: Iterable[str] = (tenant.strip() for tenant in raw.split(","))
    cleaned = sorted({tenant for tenant in candidates if tenant})
    return tuple(cleaned) or ("acme", "beta")


def _database_config() -> DatabaseConfig | None:
    """Build a database configuration when ``DATABASE_URL`` is present."""

    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        return None
    return DatabaseConfig(pool=PoolConfig(dsn=dsn))


def create_app() -> MereApp:
    """Instantiate the demo application with bootstrap routes attached."""

    config = AppConfig(
        site=os.getenv("MERE_SITE", "demo"),
        domain=os.getenv("MERE_DOMAIN", "local.test"),
        allowed_tenants=_parse_allowed_tenants(os.getenv("MERE_ALLOWED_TENANTS")),
        database=_database_config(),
    )
    app = MereApp(config, bootstrap_enabled=True)

    @app.get("/", name="root")
    async def root(request: Request) -> Response:
        tenant = request.tenant
        return JSONResponse(
            {
                "message": "Mere bootstrap is ready",
                "tenant": tenant.tenant,
                "scope": tenant.scope.value,
                "host": tenant.host,
            }
        )

    return app


def main() -> None:
    """Boot the Granian development server."""

    app = create_app()
    host = os.getenv("MERE_HOST", "127.0.0.1")
    port = int(os.getenv("MERE_PORT", "8443"))
    profile = os.getenv("MERE_PROFILE", "development")
    cert_path = os.getenv("MERE_TLS_CERT")
    key_path = os.getenv("MERE_TLS_KEY")
    ca_path = os.getenv("MERE_TLS_CA")
    client_verify_raw = os.getenv("MERE_TLS_CLIENT_VERIFY", "0")
    client_verify = client_verify_raw.lower() in {"1", "true", "yes", "on"}

    server_kwargs: dict[str, object] = {
        "host": host,
        "port": port,
        "profile": profile,
        "client_auth_required": client_verify,
    }
    if cert_path is not None:
        server_kwargs["certificate_path"] = cert_path or None
    if key_path is not None:
        server_kwargs["private_key_path"] = key_path or None
    if ca_path is not None:
        server_kwargs["ca_path"] = ca_path or None
    config = ServerConfig(**server_kwargs)
    scheme = "https" if config.certificate_path and config.private_key_path else "http"
    print(
        "Serving Mere bootstrap example on Granian at %s://%s:%d (tenants: %s)"
        % (scheme, host, port, ", ".join(app.tenant_resolver.allowed_tenants) or "<none>")
    )
    run(app, config)


if __name__ == "__main__":
    main()
