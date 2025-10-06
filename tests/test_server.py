from __future__ import annotations

import pytest

from mere.application import MereApp
from mere.config import AppConfig
from mere.server import (
    ServerConfig,
    _clear_current_app,
    _current_app_loader,
    create_server,
    run,
)


def _granian_spy(monkeypatch):
    calls: list[dict[str, object]] = []

    class DummyGranian:
        def __init__(self, target: str, **kwargs):
            calls.append({"target": target, "kwargs": kwargs})

    monkeypatch.setattr("mere.server.Granian", DummyGranian)
    return calls, DummyGranian


def test_create_server_configures_tls(monkeypatch, tmp_path) -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    certificate = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    ca = tmp_path / "ca.crt"
    for path in (certificate, key, ca):
        path.write_text("sample", encoding="utf-8")

    calls, DummyGranian = _granian_spy(monkeypatch)

    config = ServerConfig(
        host="127.0.0.1",
        port=9443,
        workers=2,
        certificate_path=certificate,
        private_key_path=key,
        ca_path=ca,
        client_auth_required=True,
        profile="production",
    )
    server = create_server(app, config)
    assert isinstance(server, DummyGranian)
    assert calls and calls[0]["target"] == "mere.server:_current_app_loader"
    kwargs = calls[0]["kwargs"]
    assert kwargs["ssl_cert"] == certificate
    assert kwargs["ssl_key"] == key
    assert kwargs["ssl_ca"] == ca
    assert kwargs["ssl_client_verify"] is True
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


def test_create_server_rejects_missing_tls(tmp_path) -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    config = ServerConfig(
        profile="production",
        certificate_path=tmp_path / "missing.crt",
        private_key_path=None,
    )
    with pytest.raises(RuntimeError, match="TLS assets required"):
        create_server(app, config)


def test_create_server_requires_client_ca_when_verification_enabled(tmp_path) -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    certificate = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    certificate.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")

    config = ServerConfig(
        profile="production",
        certificate_path=certificate,
        private_key_path=key,
        client_auth_required=True,
        ca_path=None,
    )
    with pytest.raises(RuntimeError, match="Client certificate verification"):
        create_server(app, config)


def test_create_server_rejects_missing_client_ca_file(tmp_path) -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    certificate = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    ca = tmp_path / "clients.crt"
    certificate.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")

    config = ServerConfig(
        profile="production",
        certificate_path=certificate,
        private_key_path=key,
        client_auth_required=True,
        ca_path=ca,
    )
    with pytest.raises(RuntimeError, match="Client CA bundle not found"):
        create_server(app, config)


def test_create_server_wires_ca_without_client_auth(monkeypatch, tmp_path) -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    calls, DummyGranian = _granian_spy(monkeypatch)
    certificate = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    ca = tmp_path / "clients.crt"
    for path in (certificate, key, ca):
        path.write_text("data", encoding="utf-8")

    config = ServerConfig(
        profile="production",
        certificate_path=certificate,
        private_key_path=key,
        ca_path=ca,
        client_auth_required=False,
    )
    try:
        server = create_server(app, config)
        assert isinstance(server, DummyGranian)
        kwargs = calls[0]["kwargs"]
        assert kwargs.get("ssl_ca") == ca
        assert "ssl_client_verify" not in kwargs
    finally:
        _clear_current_app()


def test_create_server_allows_plaintext_for_development(monkeypatch) -> None:
    app = MereApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    calls, DummyGranian = _granian_spy(monkeypatch)
    config = ServerConfig(
        profile="development",
        certificate_path=None,
        private_key_path=None,
        ca_path=None,
    )
    try:
        server = create_server(app, config)
        assert isinstance(server, DummyGranian)
        kwargs = calls[0]["kwargs"]
        assert "ssl_cert" not in kwargs
        assert "ssl_key" not in kwargs
        assert "ssl_ca" not in kwargs
    finally:
        _clear_current_app()
