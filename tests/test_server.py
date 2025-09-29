from __future__ import annotations

import pytest
from granian import Granian

from mere.application import MereApp
from mere.config import AppConfig
from mere.server import (
    ServerConfig,
    _clear_current_app,
    _current_app_loader,
    create_server,
    run,
)


def test_create_server_returns_granian() -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    config = ServerConfig(host="127.0.0.1", port=9000, workers=2)
    server = create_server(app, config)
    assert isinstance(server, Granian)
    try:
        assert _current_app_loader() is app
    finally:
        _clear_current_app()


def test_run_invokes_serve(monkeypatch) -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    served = {"called": False}

    class DummyServer:
        def serve(self, target_loader=None, wrap_loader=True) -> None:
            served["called"] = True
            served["loader"] = target_loader
            served["wrap"] = wrap_loader

    def fake_create(app, config=None):
        return DummyServer()

    monkeypatch.setattr("mere.server.create_server", fake_create)
    run(app)
    assert served["called"] is True
    assert served["loader"] is _current_app_loader
    assert served["wrap"] is False


def test_current_app_loader_without_registration() -> None:
    _clear_current_app()
    with pytest.raises(RuntimeError):
        _current_app_loader()
