from __future__ import annotations

from granian import Granian

from artemis.application import ArtemisApp
from artemis.config import AppConfig
from artemis.server import ServerConfig, create_server, run


def test_create_server_returns_granian() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    config = ServerConfig(host="127.0.0.1", port=9000, workers=2)
    server = create_server(app, config)
    assert isinstance(server, Granian)


def test_run_invokes_serve(monkeypatch) -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    served = {"called": False}

    class DummyServer:
        def serve(self) -> None:
            served["called"] = True

    def fake_create(app, config=None):
        return DummyServer()

    monkeypatch.setattr("artemis.server.create_server", fake_create)
    run(app)
    assert served["called"] is True
