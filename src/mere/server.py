"""Granian integration helpers."""

from __future__ import annotations

import msgspec
from granian import Granian

from .application import MereApp

_CURRENT_APP: MereApp | None = None


def _register_current_app(app: MereApp) -> None:
    """Store ``app`` for retrieval by worker processes."""

    global _CURRENT_APP
    _CURRENT_APP = app


def _clear_current_app() -> None:
    """Clear any registered application instance."""

    global _CURRENT_APP
    _CURRENT_APP = None


def _current_app_loader() -> MereApp:
    """Return the application registered for the current process."""

    if _CURRENT_APP is None:
        raise RuntimeError("no Mere application registered for Granian")
    return _CURRENT_APP


class ServerConfig(msgspec.Struct, frozen=True):
    host: str = "0.0.0.0"
    port: int = 8000
    interface: str = "asgi"
    loop: str = "rloop"
    workers: int = 1


def create_server(app: MereApp, config: ServerConfig | None = None) -> Granian:
    cfg = config or ServerConfig()
    _register_current_app(app)
    return Granian(
        "mere.server:_current_app_loader",
        address=cfg.host,
        port=cfg.port,
        interface=cfg.interface,
        loop=cfg.loop,
        workers=cfg.workers,
    )


def run(app: MereApp, config: ServerConfig | None = None) -> None:
    server = create_server(app, config)
    try:
        server.serve(target_loader=_current_app_loader, wrap_loader=False)
    finally:
        _clear_current_app()
