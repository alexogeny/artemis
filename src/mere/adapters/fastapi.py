"""Helpers for migrating FastAPI applications."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..application import MereApp

if TYPE_CHECKING:  # pragma: no cover - optional dependency typing aid
    from fastapi import FastAPI


def mount_fastapi(
    app: MereApp,
    fastapi_app: "FastAPI",
    *,
    prefix: str = "/legacy",
    name: str | None = None,
) -> None:
    """Expose a FastAPI application inside a Mere project.

    ``mount_fastapi`` wires the given ``fastapi_app`` beneath ``prefix`` using
    :meth:`MereApp.mount_asgi`. The helper also hooks the FastAPI startup and
    shutdown events into Mere's lifecycle so background tasks, dependency
    injection, and connection pools continue to work as expected.
    """

    async def _startup() -> None:
        await fastapi_app.router.startup()

    async def _shutdown() -> None:
        await fastapi_app.router.shutdown()

    app.mount_asgi(prefix, fastapi_app, name=name, startup=_startup, shutdown=_shutdown)


__all__ = ["mount_fastapi"]
