"""SOC 2 Trust Services Criteria regression tests for the Mere web framework."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import msgspec
import pytest

from mere.application import MereApp
from mere.audit import INSERT, AuditActor, AuditTrail, audit_context
from mere.database import Database, DatabaseConfig, PoolConfig
from mere.models import AdminAuditLogEntry, TenantAuditLogEntry, TenantUser
from mere.orm import default_registry
from mere.server import (
    ServerConfig,
    _clear_current_app,
    _current_app_loader,
    _ensure_client_auth,
    _granian_kwargs,
    _register_current_app,
    _require_paths,
    create_server,
)
from mere.tenancy import TenantResolver, TenantScope
from tests.support import FakeConnection, FakePool


@pytest.mark.asyncio
async def test_soc2_audit_trail_redacts_sensitive_changes() -> None:
    """SOC 2 CC7.2/CC7.4 require tamper-evident audit trails with sensitive fields redacted."""

    now = dt.datetime(2024, 4, 1, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    tenant = resolver.context_for("acme")

    actor = AuditActor(id="admin-1", type="AdminUser")
    user = TenantUser(email="user@example.com", hashed_password="super-secret")
    row = msgspec.to_builtins(user)

    async with audit_context(tenant=tenant, actor=actor):
        await trail.record_model_change(
            info=default_registry().info_for(TenantUser),
            action=INSERT,
            tenant=tenant,
            data=row,
            changes=row,
        )

    _, _, params, _ = connection.calls[-1]
    info = default_registry().info_for(TenantAuditLogEntry)
    inserted = {field.name: value for field, value in zip(info.fields, params)}
    assert inserted["action"] == "insert"
    assert inserted["metadata"]["tenant"] == "acme"
    assert inserted["changes"]["email"] == "user@example.com"
    assert "hashed_password" not in inserted["changes"]
    assert inserted["created_at"] == now


def test_soc2_tls_assets_required_outside_dev() -> None:
    """SOC 2 CC6.7 mandates TLS assets before serving production traffic."""

    paths = {
        "certificate_path": (Path("config/tls/server.crt"), False),
        "private_key_path": (Path("config/tls/server.key"), False),
    }
    with pytest.raises(RuntimeError) as excinfo:
        _require_paths(paths, profile="production")
    message = str(excinfo.value)
    assert "TLS assets required" in message
    assert "certificate_path" in message and "private_key_path" in message


def test_soc2_dev_profile_defers_tls_asset_enforcement() -> None:
    """SOC 2 CC6.7 allows relaxed TLS checks in isolated development profiles."""

    paths = {
        "certificate_path": (Path("config/tls/server.crt"), False),
        "private_key_path": (Path("config/tls/server.key"), False),
    }

    # No exception should be raised when running in a recognised development profile.
    _require_paths(paths, profile="development")


def test_soc2_client_auth_requires_trusted_ca_bundle(tmp_path: Path) -> None:
    """SOC 2 CC6.6 enforces client certificate validation with a trusted CA bundle."""

    ca_path = tmp_path / "ca.pem"
    ca_path.write_text("dummy")

    with pytest.raises(RuntimeError) as excinfo:
        _ensure_client_auth((ca_path, False), required=True)
    assert "Client CA bundle" in str(excinfo.value)

    assert _ensure_client_auth((ca_path, True), required=True) == ca_path
    assert _ensure_client_auth((ca_path, False), required=False) is None


def test_soc2_granian_kwargs_configures_mutual_tls(tmp_path: Path) -> None:
    """SOC 2 CC6.6/CC6.7 require mutual TLS enforcement in production."""

    certificate_path = tmp_path / "server.crt"
    certificate_path.write_text("cert")
    key_path = tmp_path / "server.key"
    key_path.write_text("key")
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text("ca")

    config = ServerConfig(
        certificate_path=certificate_path,
        private_key_path=key_path,
        ca_path=ca_path,
        client_auth_required=True,
        profile="production",
    )

    kwargs = _granian_kwargs(config)
    assert kwargs["ssl_cert"] == certificate_path
    assert kwargs["ssl_key"] == key_path
    assert kwargs["ssl_ca"] == ca_path
    assert kwargs["ssl_client_verify"] is True


def test_soc2_granian_kwargs_carries_optional_ca_bundle(tmp_path: Path) -> None:
    """SOC 2 CC6.7 retains trusted roots even when client auth is optional."""

    certificate_path = tmp_path / "server.crt"
    certificate_path.write_text("cert")
    key_path = tmp_path / "server.key"
    key_path.write_text("key")
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text("ca")

    config = ServerConfig(
        certificate_path=certificate_path,
        private_key_path=key_path,
        ca_path=ca_path,
        client_auth_required=False,
        profile="production",
    )

    kwargs = _granian_kwargs(config)
    assert kwargs["ssl_cert"] == certificate_path
    assert kwargs["ssl_key"] == key_path
    assert kwargs["ssl_ca"] == ca_path
    assert "ssl_client_verify" not in kwargs


def test_soc2_current_app_registration_is_controlled() -> None:
    """SOC 2 CC5.2 requires controlled promotion of the active application."""

    _clear_current_app()
    with pytest.raises(RuntimeError):
        _current_app_loader()

    app = MereApp()
    try:
        _register_current_app(app)
        assert _current_app_loader() is app
    finally:
        _clear_current_app()


@pytest.mark.asyncio
async def test_soc2_admin_audit_entries_are_isolated() -> None:
    """SOC 2 CC7.2 demands privileged actions be captured in the admin audit log."""

    now = dt.datetime(2024, 4, 2, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    admin = resolver.context_for("admin", scope=TenantScope.ADMIN)
    actor = AuditActor(id="security", type="AdminUser")

    async with audit_context(tenant=admin, actor=actor):
        await trail.record_custom(
            scope="admin",
            tenant=None,
            action="rotate-keys",
            entity_type="tls_config",
            metadata={"reason": "scheduled"},
        )

    # First call sets the admin search path, second call inserts the audit row.
    assert '"admin"' in connection.calls[0][1]
    assert '"admin"."admin_audit_log"' in connection.calls[1][1]

    info = default_registry().info_for(AdminAuditLogEntry)
    inserted = {field.name: value for field, value in zip(info.fields, connection.calls[1][2])}
    assert inserted["action"] == "rotate-keys"
    assert inserted["actor_id"] == "security"
    assert inserted["metadata"]["reason"] == "scheduled"
    assert inserted["metadata"]["tenant"] == "admin"


@pytest.mark.asyncio
async def test_soc2_tenant_audit_trail_maintains_schema_isolation() -> None:
    """SOC 2 CC6.6 requires tenant actions to be logged in tenant-scoped schemas."""

    now = dt.datetime(2024, 4, 3, tzinfo=dt.timezone.utc)
    connection = FakeConnection()
    pool = FakePool(connection)
    database = Database(DatabaseConfig(pool=PoolConfig(dsn="postgres://")), pool=pool)
    trail = AuditTrail(database, registry=default_registry(), clock=lambda: now)
    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    actor = AuditActor(id="auditor", type="SupportAgent")

    for tenant in (resolver.context_for("acme"), resolver.context_for("beta")):
        user = TenantUser(email=f"user@{tenant.tenant}.example.com", hashed_password="secret")
        row = msgspec.to_builtins(user)
        async with audit_context(tenant=tenant, actor=actor):
            await trail.record_model_change(
                info=default_registry().info_for(TenantUser),
                action=INSERT,
                tenant=tenant,
                data=row,
                changes=row,
            )

    insert_calls = [call for call in connection.calls if call[0] == "execute" and call[1].startswith("INSERT")]
    assert len(insert_calls) == 2
    info = default_registry().info_for(TenantAuditLogEntry)

    first_row = {field.name: value for field, value in zip(info.fields, insert_calls[0][2])}
    second_row = {field.name: value for field, value in zip(info.fields, insert_calls[1][2])}

    assert '"tenant_acme"' in insert_calls[0][1]
    assert '"tenant_beta"' in insert_calls[1][1]
    assert first_row["metadata"]["tenant"] == "acme"
    assert second_row["metadata"]["tenant"] == "beta"
    assert first_row["changes"]["email"].endswith("@acme.example.com")
    assert second_row["changes"]["email"].endswith("@beta.example.com")


def test_soc2_database_schema_overrides_preserve_isolation() -> None:
    """SOC 2 CC6.1 keeps tenant schemas isolated with explicit overrides."""

    resolver = TenantResolver(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
    config = DatabaseConfig(
        tenant_schema_template="tenant_{tenant}",
        tenant_schema_overrides={"beta": "tenant_beta_custom"},
    )

    acme_context = resolver.context_for("acme")
    beta_context = resolver.context_for("beta")

    assert config.schema_for_tenant(acme_context) == "tenant_acme"
    assert config.schema_for_tenant(beta_context) == "tenant_beta_custom"


def test_soc2_failed_bootstrap_rolls_back_registration(tmp_path: Path) -> None:
    """SOC 2 CC5.3 requires failed startups to roll back partially registered apps."""

    app = MereApp()
    config = ServerConfig(
        certificate_path=tmp_path / "missing.crt",
        private_key_path=tmp_path / "missing.key",
        profile="production",
    )

    with pytest.raises(RuntimeError):
        create_server(app, config)

    with pytest.raises(RuntimeError):
        _current_app_loader()

    _clear_current_app()
