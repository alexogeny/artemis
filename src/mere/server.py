"""Granian integration helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import msgspec
from granian import Granian

from .application import MereApp

_CURRENT_APP: MereApp | None = None

_DEV_PROFILES: frozenset[str] = frozenset({"development", "dev", "local", "test"})


def _normalize_path(path: str | Path | None) -> Path | None:
    """Coerce ``path`` into :class:`~pathlib.Path` instances when provided."""

    if path is None:
        return None
    return path if isinstance(path, Path) else Path(path)


def _path_state(path: str | Path | None) -> tuple[Path | None, bool]:
    """Return a tuple of the normalized path and whether it exists."""

    resolved = _normalize_path(path)
    if resolved is None:
        return None, False
    return resolved, resolved.exists()


def _require_paths(paths: Mapping[str, tuple[Path | None, bool]], *, profile: str) -> None:
    """Ensure TLS assets exist when running outside development profiles."""

    if profile.lower() in _DEV_PROFILES:
        return

    missing: list[str] = []
    for label, (path, exists) in paths.items():
        if path is None:
            missing.append(label)
        elif not exists:
            missing.append(f"{label} ({path})")
    if missing:
        formatted = ", ".join(sorted(missing))
        raise RuntimeError(f"TLS assets required for {profile!r} profile: missing {formatted}")


def _ensure_client_auth(ca_bundle: tuple[Path | None, bool], required: bool) -> Path | None:
    """Validate client-auth requirements before configuring Granian."""

    path, exists = ca_bundle
    if not required:
        return path if exists else None
    if path is None:
        raise RuntimeError("Client certificate verification requested without a CA bundle")
    if not exists:
        raise RuntimeError(f"Client CA bundle not found at {path}")
    return path


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
    port: int = 8443
    interface: str = "asgi"
    loop: str = "rloop"
    workers: int = 1
    certificate_path: str | Path | None = Path("config/tls/server.crt")
    private_key_path: str | Path | None = Path("config/tls/server.key")
    ca_path: str | Path | None = Path("config/tls/ca.crt")
    client_auth_required: bool = False
    profile: str = "production"


def _granian_kwargs(cfg: ServerConfig) -> Mapping[str, Any]:
    certificate = _path_state(cfg.certificate_path)
    key = _path_state(cfg.private_key_path)
    ca_bundle = _path_state(cfg.ca_path)

    paths: dict[str, tuple[Path | None, bool]] = {
        "certificate_path": certificate,
        "private_key_path": key,
    }
    _require_paths(paths, profile=cfg.profile)

    resolved_ca = _ensure_client_auth(ca_bundle, cfg.client_auth_required)

    kwargs: dict[str, Any] = {
        "address": cfg.host,
        "port": cfg.port,
        "interface": cfg.interface,
        "loop": cfg.loop,
        "workers": cfg.workers,
    }
    cert_path, cert_exists = certificate
    key_path, key_exists = key
    ca_path, ca_exists = ca_bundle
    if cert_exists and key_exists:
        kwargs["ssl_cert"] = cert_path
        kwargs["ssl_key"] = key_path
    if resolved_ca is not None:
        kwargs["ssl_ca"] = resolved_ca
    if cfg.client_auth_required:
        kwargs["ssl_client_verify"] = True
    elif ca_exists and ca_path is not None:
        kwargs["ssl_ca"] = ca_path
    return kwargs


def create_server(app: MereApp, config: ServerConfig | None = None) -> Granian:
    cfg = config or ServerConfig()
    _register_current_app(app)
    try:
        kwargs = _granian_kwargs(cfg)
        return Granian("mere.server:_current_app_loader", **kwargs)
    except Exception:
        _clear_current_app()
        raise


def run(app: MereApp, config: ServerConfig | None = None) -> None:
    server = create_server(app, config)
    try:
        server.serve(target_loader=_current_app_loader, wrap_loader=False)
    finally:
        _clear_current_app()
