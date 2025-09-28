"""Granian integration helpers."""

from __future__ import annotations

import msgspec
from granian import Granian

from .application import MereApp


class ServerConfig(msgspec.Struct, frozen=True):
    host: str = "0.0.0.0"
    port: int = 8000
    interface: str = "asgi"
    loop: str = "rloop"
    workers: int = 1


def create_server(app: MereApp, config: ServerConfig | None = None) -> Granian:
    cfg = config or ServerConfig()
    return Granian(
        app,
        address=cfg.host,
        port=cfg.port,
        interface=cfg.interface,
        loop=cfg.loop,
        workers=cfg.workers,
    )


def run(app: MereApp, config: ServerConfig | None = None) -> None:
    server = create_server(app, config)
    server.serve()
