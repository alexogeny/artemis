from __future__ import annotations

import datetime as dt
import json
import types
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Mapping, Sequence, cast

import msgspec
import pytest
from msgspec import structs

import mere.bootstrap as bootstrap
from mere import AppConfig, MereApp, PasskeyManager, SessionLevel, TestClient
from mere.bootstrap import (
    DEFAULT_BOOTSTRAP_AUTH,
    BootstrapAdminControlPlane,
    BootstrapAdminRealm,
    BootstrapAdminUserRecord,
    BootstrapAuthConfig,
    BootstrapAuthEngine,
    BootstrapChatOpsControlPlane,
    BootstrapChatOpsSettings,
    BootstrapKanbanCard,
    BootstrapPasskey,
    BootstrapPasskeyRecord,
    BootstrapRepository,
    BootstrapSeeder,
    BootstrapSeedStateRecord,
    BootstrapSlashCommand,
    BootstrapSlashCommandInvocation,
    BootstrapSsoProvider,
    BootstrapSupportTicketRecord,
    BootstrapSupportTicketRequest,
    BootstrapSupportTicketUpdateRequest,
    BootstrapTenant,
    BootstrapTenantRecord,
    BootstrapTenantSupportTicketRecord,
    BootstrapTenantUserRecord,
    BootstrapTrialExtensionRecord,
    BootstrapUser,
    LoginStep,
    MfaAttempt,
    PasskeyAttempt,
    PasswordAttempt,
    attach_bootstrap,
    bootstrap_migrations,
    ensure_tenant_schemas,
    load_bootstrap_auth_from_env,
)
from mere.chatops import (
    ChatMessage,
    ChatOpsCommandBinding,
    ChatOpsCommandContext,
    ChatOpsCommandRegistry,
    ChatOpsCommandResolutionError,
    ChatOpsConfig,
    ChatOpsError,
    ChatOpsService,
    ChatOpsSlashCommand,
    SlackWebhookConfig,
)
from mere.database import Database, DatabaseConfig, PoolConfig
from mere.domain.services import (
    AuditLogEntry,
    AuditLogExport,
    AuditLogPage,
    AuditService,
    DelegationRecord,
    DelegationService,
    PermissionSetRecord,
    RbacService,
    RoleAssignmentResult,
    TilePermissions,
    TileRecord,
    TileService,
)
from mere.exceptions import HTTPError
from mere.http import Status
from mere.migrations import MigrationRunner
from mere.models import (
    BillingRecord,
    BillingStatus,
    SupportTicket,
    SupportTicketKind,
    SupportTicketStatus,
    SupportTicketUpdate,
)
from mere.orm import ORM
from mere.rbac import CedarEngine
from mere.requests import Request
from mere.responses import JSONResponse, Response
from mere.tenancy import TenantContext, TenantScope
from tests.support import FakeConnection, FakePool


def _assert_error_detail(exc: pytest.ExceptionInfo[BaseException], code: str) -> None:
    err = exc.value
    assert isinstance(err, HTTPError)
    assert err.detail["detail"] == code


@pytest.mark.asyncio
async def test_bootstrap_routes_dev_environment() -> None:
    app = MereApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))

    async with TestClient(app) as client:
        for tenant in ("acme", "beta", app.config.admin_subdomain):
            ping = await client.get("/__mere/ping", tenant=tenant)
            assert ping.status == 200
            assert ping.body.decode() == "pong"

            openapi = await client.get("/__mere/openapi.json", tenant=tenant)
            assert openapi.status == 200
            spec = json.loads(openapi.body.decode())
            assert "/__mere/ping" in spec["paths"]

            client_ts = await client.get("/__mere/client.ts", tenant=tenant)
            assert client_ts.status == 200
            assert ("content-type", "application/typescript") in client_ts.headers
            assert "export class MereClient" in client_ts.body.decode()


def test_bootstrap_rejects_production() -> None:
    with pytest.raises(RuntimeError):
        MereApp(
            AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")),
            bootstrap_environment="production",
        )


def test_bootstrap_updates_allowed_tenants_from_config() -> None:
    config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="gamma",
                name="Gamma Corp",
                users=(
                    BootstrapUser(
                        id="usr_gamma_owner",
                        email="owner@gamma.test",
                        password="gamma-pass",
                    ),
                ),
            ),
        ),
        admin=DEFAULT_BOOTSTRAP_AUTH.admin,
    )

    app = MereApp(
        AppConfig(site="demo", domain="local.test", allowed_tenants=()),
        bootstrap_auth=config,
    )

    assert "gamma" in app.tenant_resolver.allowed_tenants


@pytest.mark.asyncio
async def test_bootstrap_with_root_base_path() -> None:
    app = MereApp(
        AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")),
        bootstrap_base_path="",
    )

    async with TestClient(app) as client:
        response = await client.get("/ping", tenant="acme")
        assert response.status == 200
        assert response.body.decode() == "pong"


@pytest.mark.asyncio
async def test_bootstrap_sso_login_hint() -> None:
    app = MereApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))

    async with TestClient(app) as client:
        response = await client.post(
            "/__mere/auth/login/start",
            tenant="acme",
            json={"email": "founder@acme.test"},
        )
        assert response.status == 200
        payload = json.loads(response.body.decode())
        assert payload["next"] == "sso"
        assert payload["provider"]["redirect_url"].startswith("https://id.acme.test")
        assert payload["fallback"] is None


@pytest.mark.asyncio
async def test_bootstrap_passkey_flow_with_mfa() -> None:
    app = MereApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))

    async with TestClient(app) as client:
        start = await client.post(
            "/__mere/auth/login/start",
            tenant="beta",
            json={"email": "ops@beta.test"},
        )
        assert start.status == 200
        start_payload = json.loads(start.body.decode())
        assert start_payload["next"] == "passkey"
        assert start_payload["fallback"] == "password"
        flow_token = start_payload["flow_token"]
        challenge = start_payload["challenge"]
        credential_id = start_payload["credential_ids"][0]

        user = DEFAULT_BOOTSTRAP_AUTH.tenants[1].users[0]
        passkey_cfg = user.passkeys[0]
        manager = PasskeyManager()
        demo_passkey = manager.register(
            user_id=user.id,
            credential_id=passkey_cfg.credential_id,
            secret=passkey_cfg.secret.encode("utf-8"),
            user_handle="demo",
        )
        signature = manager.sign(passkey=demo_passkey, challenge=challenge)

        passkey_response = await client.post(
            "/__mere/auth/login/passkey",
            tenant="beta",
            json={
                "flow_token": flow_token,
                "credential_id": credential_id,
                "signature": signature,
            },
        )
        assert passkey_response.status == 200
        passkey_payload = json.loads(passkey_response.body.decode())
        assert passkey_payload["next"] == "mfa"

        mfa_response = await client.post(
            "/__mere/auth/login/mfa",
            tenant="beta",
            json={"flow_token": flow_token, "code": user.mfa_code},
        )
        assert mfa_response.status == 200
        mfa_payload = json.loads(mfa_response.body.decode())
        assert mfa_payload["next"] == "success"
        session = mfa_payload["session"]
        assert session["level"] == "mfa"
        assert session["scope"] == "tenant"
        assert session["user_id"] == user.id


@pytest.mark.asyncio
async def test_bootstrap_login_flow_times_out() -> None:
    config = BootstrapAuthConfig(
        tenants=DEFAULT_BOOTSTRAP_AUTH.tenants,
        admin=DEFAULT_BOOTSTRAP_AUTH.admin,
        flow_ttl_seconds=0,
    )
    app = MereApp(
        AppConfig(site="demo", domain="local.test", allowed_tenants=("beta",)),
        bootstrap_auth=config,
    )

    async with TestClient(app) as client:
        start = await client.post(
            "/__mere/auth/login/start",
            tenant="beta",
            json={"email": "ops@beta.test"},
        )
        assert start.status == 200
        flow_token = json.loads(start.body.decode())["flow_token"]

        expired = await client.post(
            "/__mere/auth/login/password",
            tenant="beta",
            json={"flow_token": flow_token, "password": "beta-password"},
        )
        assert expired.status == Status.GONE
        expired_payload = json.loads(expired.body.decode())
        assert expired_payload["error"]["detail"]["detail"] == "flow_expired"

        restart = await client.post(
            "/__mere/auth/login/start",
            tenant="beta",
            json={"email": "ops@beta.test"},
        )
        assert restart.status == 200


@pytest.mark.asyncio
async def test_bootstrap_login_flow_locks_after_failures() -> None:
    config = BootstrapAuthConfig(
        tenants=DEFAULT_BOOTSTRAP_AUTH.tenants,
        admin=DEFAULT_BOOTSTRAP_AUTH.admin,
        max_attempts=2,
    )
    app = MereApp(
        AppConfig(site="demo", domain="local.test", allowed_tenants=("beta",)),
        bootstrap_auth=config,
    )

    async with TestClient(app) as client:
        start = await client.post(
            "/__mere/auth/login/start",
            tenant="beta",
            json={"email": "ops@beta.test"},
        )
        assert start.status == 200
        flow_token = json.loads(start.body.decode())["flow_token"]

        first_attempt = await client.post(
            "/__mere/auth/login/password",
            tenant="beta",
            json={"flow_token": flow_token, "password": "wrong"},
        )
        assert first_attempt.status == Status.UNAUTHORIZED
        first_payload = json.loads(first_attempt.body.decode())
        assert first_payload["error"]["detail"]["detail"] == "invalid_password"

        second_attempt = await client.post(
            "/__mere/auth/login/password",
            tenant="beta",
            json={"flow_token": flow_token, "password": "wrong"},
        )
        assert second_attempt.status == Status.TOO_MANY_REQUESTS
        second_payload = json.loads(second_attempt.body.decode())
        assert second_payload["error"]["detail"]["detail"] == "flow_locked"


@pytest.mark.asyncio
async def test_bootstrap_engine_prunes_expired_flows() -> None:
    engine = BootstrapAuthEngine(DEFAULT_BOOTSTRAP_AUTH)
    tenant = TenantContext(
        tenant="beta",
        site="demo",
        domain="local.test",
        scope=TenantScope.TENANT,
    )

    await engine.start(tenant, email="ops@beta.test")
    async with engine._lock:
        for flow in engine._flows.values():
            flow.expires_at = 0.0

    await engine.start(tenant, email="ops@beta.test")
    async with engine._lock:
        assert len(engine._flows) == 1


@pytest.mark.asyncio
async def test_bootstrap_password_flow_for_admin() -> None:
    app = MereApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))

    admin = DEFAULT_BOOTSTRAP_AUTH.admin.users[0]

    async with TestClient(app) as client:
        start = await client.post(
            "/__mere/auth/login/start",
            tenant=app.config.admin_subdomain,
            json={"email": admin.email},
        )
        assert start.status == 200
        start_payload = json.loads(start.body.decode())
        assert start_payload["next"] == "password"
        flow_token = start_payload["flow_token"]

        password_response = await client.post(
            "/__mere/auth/login/password",
            tenant=app.config.admin_subdomain,
            json={"flow_token": flow_token, "password": admin.password},
        )
        assert password_response.status == 200
        password_payload = json.loads(password_response.body.decode())
        assert password_payload["next"] == "mfa"

        mfa_response = await client.post(
            "/__mere/auth/login/mfa",
            tenant=app.config.admin_subdomain,
            json={"flow_token": flow_token, "code": admin.mfa_code},
        )
        assert mfa_response.status == 200
        mfa_payload = json.loads(mfa_response.body.decode())
        assert mfa_payload["next"] == "success"
        session = mfa_payload["session"]
        assert session["scope"] == "admin"
        assert session["level"] == "mfa"


@pytest.mark.asyncio
async def test_bootstrap_migrations_create_tables() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    tenant_ctx = TenantContext(tenant="acme", site="demo", domain="local.test", scope=TenantScope.TENANT)

    migrations = bootstrap_migrations()
    runner = MigrationRunner(database, migrations=migrations, tenant_provider=lambda: (tenant_ctx,))

    await ensure_tenant_schemas(database, [tenant_ctx])
    await runner.run_all(tenants=[tenant_ctx])

    statements = [sql for kind, sql, *_ in connection.calls if kind == "execute"]
    assert any("CREATE TABLE" in sql and "bootstrap_tenants" in sql for sql in statements)
    assert any("CREATE TABLE" in sql and "bootstrap_users" in sql for sql in statements)
    assert any("CREATE TABLE" in sql and '"billing"' in sql for sql in statements)
    assert any("CREATE TABLE" in sql and "bootstrap_trial_extensions" in sql for sql in statements)
    assert any("CREATE TABLE" in sql and "dashboard_tiles" in sql for sql in statements)
    assert any("CREATE TABLE" in sql and "dashboard_tile_permissions" in sql for sql in statements)
    assert any("CREATE TABLE" in sql and "workspace_permission_sets" in sql for sql in statements)
    assert any("CREATE TABLE" in sql and "workspace_role_assignments" in sql for sql in statements)


@pytest.mark.asyncio
async def test_bootstrap_admin_billing_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme", "beta"),
        database=db_config,
    )
    app = MereApp(config=config, database=database, bootstrap_enabled=False)

    async def _noop_apply(
        self: bootstrap.BootstrapSeeder,
        config: BootstrapAuthConfig,
        *,
        tenants: Mapping[str, TenantContext],
    ) -> bool:
        return False

    monkeypatch.setattr(bootstrap.BootstrapSeeder, "apply", _noop_apply)

    async def _noop_run_all(
        self: bootstrap.MigrationRunner,
        *,
        tenants: Sequence[TenantContext],
    ) -> None:
        return None

    monkeypatch.setattr(bootstrap.MigrationRunner, "run_all", _noop_run_all)

    empty_auth = BootstrapAuthConfig(tenants=(), admin=BootstrapAdminRealm(users=()))
    attach_bootstrap(app, auth_config=empty_auth)

    orm = cast(ORM, app.orm)
    cycle_start = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    cycle_end = dt.datetime(2024, 2, 1, tzinfo=dt.timezone.utc)
    seeded_record = BillingRecord(
        customer_id="cust_acme",
        plan_code="pro",
        status=BillingStatus.ACTIVE,
        amount_due_cents=5000,
        currency="USD",
        cycle_start=cycle_start,
        cycle_end=cycle_end,
    )
    connection.queue_result([msgspec.to_builtins(seeded_record)])
    await orm.admin.billing.create(seeded_record)

    async with TestClient(app) as client:
        connection.queue_result([msgspec.to_builtins(seeded_record)])
        admin_response = await client.get(
            "/__mere/admin/billing",
            tenant=app.config.admin_subdomain,
        )
        assert admin_response.status == Status.OK
        admin_payload = json.loads(admin_response.body.decode())
        assert admin_payload[0]["customer_id"] == "cust_acme"

        tenant_response = await client.get(
            "/__mere/admin/billing",
            tenant="acme",
        )
        assert tenant_response.status == Status.FORBIDDEN

        new_cycle_start = dt.datetime(2024, 3, 1, tzinfo=dt.timezone.utc)
        new_cycle_end = dt.datetime(2024, 4, 1, tzinfo=dt.timezone.utc)
        created_record = BillingRecord(
            id="billing_gamma",
            customer_id="cust_gamma",
            plan_code="starter",
            status=BillingStatus.PAST_DUE,
            amount_due_cents=1200,
            currency="USD",
            cycle_start=new_cycle_start,
            cycle_end=new_cycle_end,
            created_at=new_cycle_start,
            updated_at=new_cycle_start,
            metadata={"notes": "manual"},
        )
        connection.queue_result([msgspec.to_builtins(created_record)])
        create_response = await client.post(
            "/__mere/admin/billing",
            tenant=app.config.admin_subdomain,
            json={
                "customer_id": "cust_gamma",
                "plan_code": "starter",
                "status": BillingStatus.PAST_DUE.value,
                "amount_due_cents": 1200,
                "currency": "USD",
                "cycle_start": new_cycle_start.isoformat(),
                "cycle_end": new_cycle_end.isoformat(),
                "metadata": {"notes": "manual"},
            },
        )
        assert create_response.status == 201
        created_payload = json.loads(create_response.body.decode())
        assert created_payload["id"] == created_record.id
        assert created_payload["metadata"]["notes"] == "manual"

        denied_create = await client.post(
            "/__mere/admin/billing",
            tenant="acme",
            json={
                "customer_id": "cust_blocked",
                "plan_code": "basic",
                "status": BillingStatus.ACTIVE.value,
                "amount_due_cents": 1000,
                "currency": "USD",
                "cycle_start": new_cycle_start.isoformat(),
                "cycle_end": new_cycle_end.isoformat(),
            },
        )
        assert denied_create.status == Status.FORBIDDEN


@pytest.mark.asyncio
async def test_bootstrap_tenant_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme", "beta"),
        database=db_config,
    )
    app = MereApp(config=config, database=database, bootstrap_enabled=False)

    async def _noop_apply(
        self: bootstrap.BootstrapSeeder,
        config: BootstrapAuthConfig,
        *,
        tenants: Mapping[str, TenantContext],
    ) -> bool:
        return False

    monkeypatch.setattr(bootstrap.BootstrapSeeder, "apply", _noop_apply)

    async def _noop_run_all(
        self: bootstrap.MigrationRunner,
        *,
        tenants: Sequence[TenantContext],
    ) -> None:
        return None

    monkeypatch.setattr(bootstrap.MigrationRunner, "run_all", _noop_run_all)

    empty_auth = BootstrapAuthConfig(tenants=(), admin=BootstrapAdminRealm(users=()))
    attach_bootstrap(app, auth_config=empty_auth)

    orm = cast(ORM, app.orm)
    acme_record = BootstrapTenantRecord(slug="acme", name="Acme Rockets")
    connection.queue_result([msgspec.to_builtins(acme_record)])
    await orm.admin.bootstrap_tenants.create(acme_record)
    beta_record = BootstrapTenantRecord(slug="beta", name="Beta Industries")
    connection.queue_result([msgspec.to_builtins(beta_record)])
    await orm.admin.bootstrap_tenants.create(beta_record)

    async with TestClient(app) as client:
        connection.queue_result(
            [
                msgspec.to_builtins(acme_record),
                msgspec.to_builtins(beta_record),
            ]
        )
        admin_response = await client.get(
            "/__mere/tenants",
            tenant=app.config.admin_subdomain,
        )
        assert admin_response.status == Status.OK
        admin_payload = json.loads(admin_response.body.decode())
        assert {item["slug"] for item in admin_payload} == {"acme", "beta"}

        connection.queue_result([msgspec.to_builtins(acme_record)])
        acme_response = await client.get("/__mere/tenants", tenant="acme")
        assert acme_response.status == Status.OK
        acme_payload = json.loads(acme_response.body.decode())
        assert acme_payload[0]["name"] == "Acme Rockets"

        connection.queue_result([msgspec.to_builtins(beta_record)])
        beta_response = await client.get("/__mere/tenants", tenant="beta")
        assert beta_response.status == Status.OK
        beta_payload = json.loads(beta_response.body.decode())
        assert beta_payload[0]["slug"] == "beta"

        gamma_created = BootstrapTenantRecord(
            id="tenant_gamma",
            slug="gamma",
            name="Gamma Co",
            created_at=dt.datetime(2024, 5, 1, tzinfo=dt.timezone.utc),
            updated_at=dt.datetime(2024, 5, 1, tzinfo=dt.timezone.utc),
        )

        async def _stub_create(
            data: Mapping[str, object] | BootstrapTenantRecord,
            *,
            tenant: TenantContext | None = None,
        ) -> BootstrapTenantRecord:
            return gamma_created

        monkeypatch.setattr(orm.admin.bootstrap_tenants, "create", _stub_create)

        connection.queue_result([])
        create_response = await client.post(
            "/__mere/tenants",
            tenant=app.config.admin_subdomain,
            json={"slug": "gamma", "name": "Gamma Co"},
        )
        assert create_response.status == 201
        created_payload = json.loads(create_response.body.decode())
        assert created_payload["slug"] == "gamma"
        assert "gamma" in app.tenant_resolver.allowed_tenants

        connection.queue_result([msgspec.to_builtins(gamma_created)])
        gamma_response = await client.get("/__mere/tenants", tenant="gamma")
        assert gamma_response.status == Status.OK
        gamma_payload = json.loads(gamma_response.body.decode())
        assert gamma_payload[0]["slug"] == "gamma"

        ping_response = await client.get("/__mere/ping", tenant="gamma")
        assert ping_response.status == Status.OK

        scope_request = Request(
            method="GET",
            path="/__mere/tenants",
            tenant=TenantContext(
                tenant=app.config.admin_subdomain,
                site=app.config.site,
                domain=app.config.domain,
                scope=TenantScope.ADMIN,
            ),
        )
        scope = app.dependencies.scope(scope_request)
        engine = await scope.get(BootstrapAuthEngine)
        assert any(tenant.slug == "gamma" for tenant in engine.config.tenants)

        denied_response = await client.post(
            "/__mere/tenants",
            tenant="acme",
            json={"slug": "delta", "name": "Delta"},
        )
        assert denied_response.status == Status.FORBIDDEN

        invalid_slug = await client.post(
            "/__mere/tenants",
            tenant=app.config.admin_subdomain,
            json={"slug": "!!bad!!", "name": "Broken"},
        )
        assert invalid_slug.status == Status.BAD_REQUEST
        invalid_slug_payload = json.loads(invalid_slug.body.decode())
        assert invalid_slug_payload["error"]["detail"]["detail"] == "invalid_slug"

        invalid_name = await client.post(
            "/__mere/tenants",
            tenant=app.config.admin_subdomain,
            json={"slug": "delta", "name": "   "},
        )
        assert invalid_name.status == Status.BAD_REQUEST
        invalid_name_payload = json.loads(invalid_name.body.decode())
        assert invalid_name_payload["error"]["detail"]["detail"] == "invalid_name"

        reserved_slug = await client.post(
            "/__mere/tenants",
            tenant=app.config.admin_subdomain,
            json={"slug": app.config.admin_subdomain, "name": "Admin"},
        )
        assert reserved_slug.status == 409
        reserved_payload = json.loads(reserved_slug.body.decode())
        assert reserved_payload["error"]["detail"]["detail"] == "slug_reserved"

        connection.queue_result([msgspec.to_builtins(gamma_created)])
        duplicate = await client.post(
            "/__mere/tenants",
            tenant=app.config.admin_subdomain,
            json={"slug": "gamma", "name": "Gamma Again"},
        )
        assert duplicate.status == 409
        duplicate_payload = json.loads(duplicate.body.decode())
        assert duplicate_payload["error"]["detail"]["detail"] == "tenant_exists"


@pytest.mark.asyncio
async def test_bootstrap_chatops_configuration_and_slash_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme", "beta"),
        database=db_config,
    )
    app = MereApp(config=config, database=database, bootstrap_enabled=False)

    class RecordingChatOpsService(ChatOpsService):
        def __init__(
            self,
            config: ChatOpsConfig,
            *,
            transport: object | None = None,
            observability: object | None = None,
        ) -> None:
            super().__init__(config)
            self.sent: list[tuple[TenantContext, ChatMessage]] = []
            self.fail_on_events: set[str] = set()

        async def send(self, tenant: TenantContext, message: ChatMessage) -> None:
            event_name = message.extra.get("event")
            if isinstance(event_name, str) and event_name in self.fail_on_events:
                raise ChatOpsError("forced")
            self.sent.append((tenant, message))

    async def _noop_apply(
        self: bootstrap.BootstrapSeeder,
        config: BootstrapAuthConfig,
        *,
        tenants: Mapping[str, TenantContext],
    ) -> bool:
        return False

    async def _noop_run_all(
        self: bootstrap.MigrationRunner,
        *,
        tenants: Sequence[TenantContext],
    ) -> None:
        return None

    monkeypatch.setattr(bootstrap.BootstrapSeeder, "apply", _noop_apply)
    monkeypatch.setattr(bootstrap.MigrationRunner, "run_all", _noop_run_all)
    monkeypatch.setattr(bootstrap, "ChatOpsService", RecordingChatOpsService)

    attach_bootstrap(app)
    orm = cast(ORM, app.orm)

    created_tenants: dict[str, BootstrapTenantRecord] = {}

    async def _stub_get(
        *,
        filters: Mapping[str, object] | None = None,
        tenant: TenantContext | None = None,
    ) -> BootstrapTenantRecord | None:
        slug = cast(str | None, (filters or {}).get("slug"))
        if slug is None:
            return None
        return created_tenants.get(slug)

    async def _stub_create(
        data: Mapping[str, object] | BootstrapTenantRecord,
        *,
        tenant: TenantContext | None = None,
    ) -> BootstrapTenantRecord:
        if isinstance(data, Mapping):
            record = BootstrapTenantRecord(
                slug=cast(str, data["slug"]),
                name=cast(str, data["name"]),
            )
        else:
            record = data
        created_tenants[record.slug] = record
        return record

    monkeypatch.setattr(orm.admin.bootstrap_tenants, "get", _stub_get)
    monkeypatch.setattr(orm.admin.bootstrap_tenants, "create", _stub_create)

    recorded_extensions: list[bootstrap.BootstrapTrialExtensionRecord] = []

    async def _stub_extension_create(
        record: bootstrap.BootstrapTrialExtensionRecord,
        *,
        tenant: TenantContext | None = None,
    ) -> bootstrap.BootstrapTrialExtensionRecord:
        recorded_extensions.append(record)
        return record

    monkeypatch.setattr(
        orm.admin.bootstrap_trial_extensions,
        "create",
        _stub_extension_create,
    )

    admin_support_tickets: dict[str, bootstrap.BootstrapSupportTicketRecord] = {}
    tenant_support_tickets: defaultdict[str, dict[str, bootstrap.BootstrapTenantSupportTicketRecord]] = defaultdict(
        dict
    )

    async def _admin_support_create(
        record: bootstrap.BootstrapSupportTicketRecord,
        *,
        tenant: TenantContext | None = None,
    ) -> bootstrap.BootstrapSupportTicketRecord:
        admin_support_tickets[record.id] = record
        return record

    async def _admin_support_get(
        *,
        filters: Mapping[str, object] | None = None,
        tenant: TenantContext | None = None,
    ) -> bootstrap.BootstrapSupportTicketRecord | None:
        if not filters:
            return None
        ticket_id = cast(str | None, filters.get("id"))
        if ticket_id is None:
            return None
        return admin_support_tickets.get(ticket_id)

    async def _admin_support_list(
        *,
        order_by: Sequence[str] | tuple[str, ...] = (),
        tenant: TenantContext | None = None,
    ) -> list[bootstrap.BootstrapSupportTicketRecord]:
        tickets = list(admin_support_tickets.values())
        if order_by:
            field_spec = order_by[0]
            field, _, direction = field_spec.partition(" ")
            reverse = direction.lower() == "desc"
            tickets.sort(key=lambda item: getattr(item, field), reverse=reverse)
        return tickets

    async def _admin_support_update(
        *,
        filters: Mapping[str, object] | None = None,
        values: Mapping[str, object],
        tenant: TenantContext | None = None,
    ) -> bootstrap.BootstrapSupportTicketRecord:
        ticket_id = cast(str, (filters or {}).get("id"))
        existing = admin_support_tickets[ticket_id]
        data = msgspec.to_builtins(existing)
        data.update(values)
        updated = msgspec.convert(data, type=bootstrap.BootstrapSupportTicketRecord)
        admin_support_tickets[ticket_id] = updated
        return updated

    async def _tenant_support_create(
        data: bootstrap.BootstrapTenantSupportTicketRecord | None = None,
        *,
        tenant: TenantContext,
        model: bootstrap.BootstrapTenantSupportTicketRecord | None = None,
    ) -> bootstrap.BootstrapTenantSupportTicketRecord:
        entry = model or data
        assert entry is not None
        tenant_support_tickets[tenant.tenant][entry.admin_ticket_id] = entry
        return entry

    async def _tenant_support_get(
        *,
        filters: Mapping[str, object] | None = None,
        tenant: TenantContext,
    ) -> bootstrap.BootstrapTenantSupportTicketRecord | None:
        if not filters:
            return None
        ticket_id = cast(str | None, filters.get("admin_ticket_id"))
        if ticket_id is None:
            return None
        return tenant_support_tickets[tenant.tenant].get(ticket_id)

    async def _tenant_support_list(
        *,
        tenant: TenantContext,
        order_by: Sequence[str] | tuple[str, ...] = (),
    ) -> list[bootstrap.BootstrapTenantSupportTicketRecord]:
        tickets = list(tenant_support_tickets[tenant.tenant].values())
        if order_by:
            field_spec = order_by[0]
            field, _, direction = field_spec.partition(" ")
            reverse = direction.lower() == "desc"
            tickets.sort(key=lambda item: getattr(item, field), reverse=reverse)
        return tickets

    async def _tenant_support_update(
        *,
        filters: Mapping[str, object] | None = None,
        values: Mapping[str, object],
        tenant: TenantContext,
    ) -> bootstrap.BootstrapTenantSupportTicketRecord:
        ticket_id = cast(str, (filters or {}).get("admin_ticket_id"))
        existing = tenant_support_tickets[tenant.tenant][ticket_id]
        data = msgspec.to_builtins(existing)
        data.update(values)
        updated = msgspec.convert(
            data,
            type=bootstrap.BootstrapTenantSupportTicketRecord,
        )
        tenant_support_tickets[tenant.tenant][ticket_id] = updated
        return updated

    monkeypatch.setattr(orm.admin.support_tickets, "create", _admin_support_create)
    monkeypatch.setattr(orm.admin.support_tickets, "get", _admin_support_get)
    monkeypatch.setattr(orm.admin.support_tickets, "list", _admin_support_list)
    monkeypatch.setattr(orm.admin.support_tickets, "update", _admin_support_update)
    monkeypatch.setattr(
        orm.tenants.support_tickets,
        "create",
        _tenant_support_create,
    )
    monkeypatch.setattr(
        orm.tenants.support_tickets,
        "get",
        _tenant_support_get,
    )
    monkeypatch.setattr(
        orm.tenants.support_tickets,
        "list",
        _tenant_support_list,
    )
    monkeypatch.setattr(
        orm.tenants.support_tickets,
        "update",
        _tenant_support_update,
    )

    async with TestClient(app) as client:
        admin = app.config.admin_subdomain
        settings_response = await client.get("/__mere/admin/chatops", tenant=admin)
        assert settings_response.status == Status.OK
        settings_payload = json.loads(settings_response.body.decode())
        assert settings_payload["enabled"] is False
        assert settings_payload["slash_commands"] == []

        update_response = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                "enabled": True,
                "webhook": {
                    "webhook_url": "https://hooks.slack.com/services/demo",
                    "default_channel": "#alerts",
                    "username": "Mere",
                },
                "notifications": {
                    "tenant_created": "#tenants",
                    "billing_updated": "#billing",
                    "subscription_past_due": "#alerts",
                },
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert update_response.status == Status.OK
        updated_payload = json.loads(update_response.body.decode())
        assert updated_payload["enabled"] is True
        assert updated_payload["notifications"]["tenant_created"] == "#tenants"
        assert any(command["action"] == "create_tenant" for command in updated_payload["slash_commands"])
        assert all(command["visibility"] == "admin" for command in updated_payload["slash_commands"])
        assert {command["name"] for command in updated_payload["slash_commands"]} == {
            "create-tenant",
            "extend-trial",
            "tenant-metrics",
            "system-diagnostics",
            "ticket-update",
        }
        commands_payload = updated_payload["slash_commands"]
        base_update = {
            "enabled": True,
            "webhook": updated_payload["webhook"],
            "notifications": updated_payload["notifications"],
        }
        initial_commands = list(commands_payload)

        chatops_service = cast(RecordingChatOpsService, app.chatops)
        chatops_service.fail_on_events.add("subscription_past_due")

        create_response = await client.post(
            "/__mere/tenants",
            tenant=admin,
            json={"slug": "gamma", "name": "Gamma Org"},
        )
        assert create_response.status == 201
        tenant_payload = json.loads(create_response.body.decode())
        assert tenant_payload["slug"] == "gamma"
        assert len(chatops_service.sent) == 1
        tenant_message = chatops_service.sent[0][1]
        assert tenant_message.channel == "#tenants"
        assert "gamma" in tenant_message.text.lower()

        past_due_start = dt.datetime(2024, 5, 1, tzinfo=dt.timezone.utc)
        past_due_end = dt.datetime(2024, 6, 1, tzinfo=dt.timezone.utc)
        created_record = BillingRecord(
            id="billing_gamma",
            customer_id="cust_gamma",
            plan_code="starter",
            status=BillingStatus.PAST_DUE,
            amount_due_cents=1200,
            currency="USD",
            cycle_start=past_due_start,
            cycle_end=past_due_end,
            created_at=past_due_start,
            updated_at=past_due_start,
        )
        connection.queue_result([msgspec.to_builtins(created_record)])
        billing_response = await client.post(
            "/__mere/admin/billing",
            tenant=admin,
            json={
                "customer_id": created_record.customer_id,
                "plan_code": created_record.plan_code,
                "status": created_record.status.value,
                "amount_due_cents": created_record.amount_due_cents,
                "currency": created_record.currency,
                "cycle_start": past_due_start.isoformat(),
                "cycle_end": past_due_end.isoformat(),
            },
        )
        assert billing_response.status == 201
        assert len(chatops_service.sent) == 2
        billing_message = chatops_service.sent[1][1]
        assert billing_message.channel == "#billing"
        assert created_record.customer_id in billing_message.text
        assert not any(message.extra.get("event") == "subscription_past_due" for _, message in chatops_service.sent)

        active_record = BillingRecord(
            id="billing_active",
            customer_id="cust_active",
            plan_code="starter",
            status=BillingStatus.ACTIVE,
            amount_due_cents=5000,
            currency="USD",
            cycle_start=past_due_end,
            cycle_end=past_due_end + dt.timedelta(days=30),
            created_at=past_due_end,
            updated_at=past_due_end,
        )
        connection.queue_result([msgspec.to_builtins(active_record)])
        active_response = await client.post(
            "/__mere/admin/billing",
            tenant=admin,
            json={
                "customer_id": active_record.customer_id,
                "plan_code": active_record.plan_code,
                "status": active_record.status.value,
                "amount_due_cents": active_record.amount_due_cents,
                "currency": active_record.currency,
                "cycle_start": active_record.cycle_start.isoformat(),
                "cycle_end": active_record.cycle_end.isoformat(),
            },
        )
        assert active_response.status == 201
        assert chatops_service.sent[-1][1].extra["event"] == "billing_updated"

        slash_create = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> create-tenant slug=omega note=demo extra-token name=Omega",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert slash_create.status == Status.OK
        slash_payload = json.loads(slash_create.body.decode())
        assert slash_payload["tenant"]["slug"] == "omega"
        assert "omega" in created_tenants
        assert len(chatops_service.sent) == 4
        slash_message = chatops_service.sent[3][1]
        assert slash_message.channel == "#tenants"
        assert "omega" in slash_message.text.lower()

        legacy_slash = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "command": "/bootstrap-create-tenant",
                "text": "slug=sigma name=Sigma",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert legacy_slash.status == Status.OK
        legacy_payload = json.loads(legacy_slash.body.decode())
        assert legacy_payload["tenant"]["slug"] == "sigma"
        assert "sigma" in created_tenants
        assert len(chatops_service.sent) == 5
        sigma_message = chatops_service.sent[4][1]
        assert "sigma" in sigma_message.text.lower()

        extend_trial = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> extend-trial tenant=gamma days=14 note=demo",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert extend_trial.status == Status.OK
        extend_payload = json.loads(extend_trial.body.decode())
        assert extend_payload["extension"]["tenant_slug"] == "gamma"
        assert recorded_extensions[-1].tenant_slug == "gamma"
        assert recorded_extensions[-1].extended_days == 14
        assert len(chatops_service.sent) == 6
        extension_message = chatops_service.sent[5][1]
        assert extension_message.channel is None
        assert "extended" in extension_message.text.lower()
        assert chatops_service.sent[-1][0].scope is TenantScope.ADMIN

        support_create = await client.post(
            "/__mere/support/tickets",
            tenant="acme",
            json={
                "subject": "Login issue",
                "message": "Cannot access dashboard",
                "kind": "issue",
            },
        )
        assert support_create.status == Status.CREATED
        ticket_payload = json.loads(support_create.body.decode())
        ticket_id = ticket_payload["id"]
        assert ticket_payload.get("status", "open") == "open"
        assert len(chatops_service.sent) == 7
        created_ticket_message = chatops_service.sent[6][1]
        assert created_ticket_message.extra["ticket_id"] == ticket_id
        assert created_ticket_message.extra["tenant"] == "acme"

        admin_support_empty = await client.get(
            "/__mere/support/tickets",
            tenant=admin,
        )
        assert admin_support_empty.status == Status.OK
        assert json.loads(admin_support_empty.body.decode()) == []

        admin_support_forbidden = await client.post(
            "/__mere/support/tickets",
            tenant=admin,
            json={
                "subject": "Admin ticket",
                "message": "Should fail",
                "kind": "general",
            },
        )
        assert admin_support_forbidden.status == Status.FORBIDDEN

        tenant_ticket_list = await client.get(
            "/__mere/support/tickets",
            tenant="acme",
        )
        assert tenant_ticket_list.status == Status.OK
        tenant_ticket_payload = json.loads(tenant_ticket_list.body.decode())
        assert tenant_ticket_payload[0]["admin_ticket_id"] == ticket_id

        admin_ticket_list = await client.get(
            "/__mere/admin/support/tickets",
            tenant=admin,
        )
        assert admin_ticket_list.status == Status.OK
        admin_ticket_payload = json.loads(admin_ticket_list.body.decode())
        assert admin_ticket_payload[0]["id"] == ticket_id

        metrics_response = await client.get(
            "/__mere/admin/metrics",
            tenant=admin,
        )
        assert metrics_response.status == Status.OK
        metrics_payload = json.loads(metrics_response.body.decode())
        assert metrics_payload["support_tickets"]["open"] == 1
        assert metrics_payload["support_tickets"]["resolved"] == 0

        diagnostics_response = await client.get(
            "/__mere/admin/diagnostics",
            tenant=admin,
        )
        assert diagnostics_response.status == Status.OK
        diagnostics_payload = json.loads(diagnostics_response.body.decode())
        assert diagnostics_payload["support"]["open"] == 1

        metrics_slash = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> tenant-metrics",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert metrics_slash.status == Status.OK
        metrics_slash_payload = json.loads(metrics_slash.body.decode())
        assert metrics_slash_payload["metrics"]["support_tickets"]["open"] == 1

        diagnostics_slash = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> system-diagnostics",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert diagnostics_slash.status == Status.OK
        diag_slash_payload = json.loads(diagnostics_slash.body.decode())
        assert diag_slash_payload["diagnostics"]["support"]["open"] == 1

        admin_ticket_update = await client.post(
            f"/__mere/admin/support/tickets/{ticket_id}",
            tenant=admin,
            json={"status": "responded", "note": "Acknowledged"},
        )
        assert admin_ticket_update.status == Status.OK
        assert len(chatops_service.sent) == 8
        responded_message = chatops_service.sent[7][1]
        assert responded_message.extra["status"] == "responded"

        ticket_update = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": f"<@U999> ticket-update ticket={ticket_id} status=resolved note=Fixed",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert ticket_update.status == Status.OK
        ticket_update_payload = json.loads(ticket_update.body.decode())
        assert ticket_update_payload["ticket"]["status"] == "resolved"
        assert len(chatops_service.sent) == 9
        resolved_message = chatops_service.sent[8][1]
        assert resolved_message.extra["status"] == "resolved"

        missing_ticket_args = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": f"<@U999> ticket-update ticket={ticket_id}",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert missing_ticket_args.status == Status.BAD_REQUEST

        invalid_ticket_status = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": f"<@U999> ticket-update ticket={ticket_id} status=invalid",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert invalid_ticket_status.status == Status.BAD_REQUEST

        metrics_after_update = await client.get(
            "/__mere/admin/metrics",
            tenant=admin,
        )
        metrics_after_payload = json.loads(metrics_after_update.body.decode())
        assert metrics_after_payload["support_tickets"]["open"] == 0
        assert metrics_after_payload["support_tickets"]["resolved"] == 1

        missing_webhook = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={"enabled": True},
        )
        assert missing_webhook.status == Status.BAD_REQUEST

        unknown_command = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> unknown",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert unknown_command.status == Status.NOT_FOUND

        invalid_mention = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U000> create-tenant slug=bad name=Bad",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert invalid_mention.status == Status.FORBIDDEN

        at_mention_create = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "@U999 create-tenant slug=phi name=Phi",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert at_mention_create.status == Status.OK
        at_payload = json.loads(at_mention_create.body.decode())
        assert at_payload["tenant"]["slug"] == "phi"
        assert "phi" in created_tenants

        bare_token_create = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "U999 create-tenant slug=chi name=Chi",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert bare_token_create.status == Status.OK
        bare_payload = json.loads(bare_token_create.body.decode())
        assert bare_payload["tenant"]["slug"] == "chi"
        assert "chi" in created_tenants

        missing_command_token = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999>",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert missing_command_token.status == Status.BAD_REQUEST

        empty_text = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert empty_text.status == Status.BAD_REQUEST

        missing_create_args = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> create-tenant slug=delta",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert missing_create_args.status == Status.BAD_REQUEST

        workspace_forbidden = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> create-tenant slug=theta name=Theta",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T999",
            },
        )
        assert workspace_forbidden.status == Status.FORBIDDEN

        missing_workspace = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> create-tenant slug=iota name=Iota",
                "user_id": "U123",
                "user_name": "demo",
            },
        )
        assert missing_workspace.status == Status.FORBIDDEN

        missing_extend_days = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> extend-trial tenant=gamma",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert missing_extend_days.status == Status.BAD_REQUEST

        invalid_days = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> extend-trial tenant=gamma days=abc",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert invalid_days.status == Status.BAD_REQUEST

        zero_days = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> extend-trial tenant=gamma days=0",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert zero_days.status == Status.BAD_REQUEST

        invalid_slug = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> extend-trial tenant=!!bad!! days=10",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert invalid_slug.status == Status.BAD_REQUEST

        missing_tenant = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> extend-trial tenant=unknown days=5",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert missing_tenant.status == Status.NOT_FOUND

        disable_bot = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": commands_payload,
                "bot_user_id": None,
                "admin_workspace": "T123",
            },
        )
        assert disable_bot.status == Status.OK
        disabled_payload = json.loads(disable_bot.body.decode())
        commands_payload = disabled_payload["slash_commands"]

        no_bot = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "text": "<@U999> create-tenant slug=upsilon name=Upsilon",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert no_bot.status == Status.BAD_REQUEST

        restore_bot = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": commands_payload,
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert restore_bot.status == Status.OK
        restored_payload = json.loads(restore_bot.body.decode())
        commands_payload = restored_payload["slash_commands"]

        tenant_forbidden = await client.post(
            "/__mere/chatops/slash",
            tenant="acme",
            json={
                "command": "/create-tenant",
                "text": "slug=rho name=Rho",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert tenant_forbidden.status == Status.FORBIDDEN

        public_commands = list(commands_payload)
        public_commands.append(
            {
                "name": "demo-extend",
                "action": "extend_trial",
                "description": "Public trial extension",
                "visibility": "public",
            }
        )
        public_update = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": public_commands,
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert public_update.status == Status.OK
        public_payload = json.loads(public_update.body.decode())
        commands_payload = public_payload["slash_commands"]

        chatops_service = cast(RecordingChatOpsService, app.chatops)
        chatops_service.config = ChatOpsConfig(enabled=False)
        unconfigured_public = await client.post(
            "/__mere/chatops/slash",
            tenant="acme",
            json={
                "text": "<@U999> demo-extend",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert unconfigured_public.status == Status.FORBIDDEN
        unconfigured_payload = json.loads(unconfigured_public.body.decode())
        assert unconfigured_payload["error"]["detail"]["detail"] == "chatops_unconfigured"
        chatops_service.config = ChatOpsConfig(
            enabled=True,
            default=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/demo"),
        )

        configured_public = await client.post(
            "/__mere/chatops/slash",
            tenant="acme",
            json={
                "text": "<@U999> demo-extend tenant=gamma days=2",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert configured_public.status == Status.OK
        configured_payload = json.loads(configured_public.body.decode())
        assert configured_payload["action"] == "extend_trial"
        assert recorded_extensions[-1].extended_days == 2

        invalid_command_update = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": [
                    {
                        "name": "Invalid Name",
                        "action": "create_tenant",
                        "description": "Invalid",
                        "visibility": "admin",
                    }
                ],
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert invalid_command_update.status == Status.BAD_REQUEST

        duplicate_command_update = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": [commands_payload[0], commands_payload[0]],
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert duplicate_command_update.status == Status.BAD_REQUEST

        invalid_alias_update = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": [
                    {
                        "name": "alias-test",
                        "action": "create_tenant",
                        "description": "Alias validation",
                        "visibility": "admin",
                        "aliases": ["Invalid Alias"],
                    }
                ],
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert invalid_alias_update.status == Status.BAD_REQUEST

        duplicate_alias_update = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": [
                    {
                        "name": "alias-test",
                        "action": "create_tenant",
                        "description": "Alias duplicate",
                        "visibility": "admin",
                        "aliases": ["alias-test", "alias-test"],
                    }
                ],
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert duplicate_alias_update.status == Status.OK
        alias_payload = json.loads(duplicate_alias_update.body.decode())
        assert alias_payload["slash_commands"][0]["aliases"] == []
        commands_payload = initial_commands

        refresh_commands = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": commands_payload,
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert refresh_commands.status == Status.OK
        commands_payload = json.loads(refresh_commands.body.decode())["slash_commands"]

        disable_integration = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": commands_payload,
                "bot_user_id": "U999",
                "admin_workspace": "T123",
                "webhook": None,
                "enabled": False,
            },
        )
        assert disable_integration.status == Status.OK

        disabled_invocation = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "command": "/bootstrap-create-tenant",
                "text": "slug=omega name=Omega",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert disabled_invocation.status == Status.FORBIDDEN
        disabled_payload = json.loads(disabled_invocation.body.decode())
        assert disabled_payload["error"]["detail"]["detail"] == "chatops_disabled"

        reenable_integration = await client.post(
            "/__mere/admin/chatops",
            tenant=admin,
            json={
                **base_update,
                "slash_commands": commands_payload,
                "bot_user_id": "U999",
                "admin_workspace": "T123",
            },
        )
        assert reenable_integration.status == Status.OK
        commands_payload = json.loads(reenable_integration.body.decode())["slash_commands"]

        create_binding = app.chatops_commands.binding_by_name("bootstrap.chatops.create_tenant")

        async def response_handler(context: ChatOpsCommandContext) -> Response:
            return JSONResponse(
                {
                    "status": "ok",
                    "action": "create_tenant",
                    "tenant": {"slug": context.args.get("slug")},
                }
            )

        app.chatops_commands.register(
            ChatOpsCommandBinding(
                command=create_binding.command,
                handler=response_handler,
                name=create_binding.name,
            )
        )

        response_invocation = await client.post(
            "/__mere/chatops/slash",
            tenant=admin,
            json={
                "command": "/bootstrap-create-tenant",
                "text": "slug=psi name=Psi",
                "user_id": "U123",
                "user_name": "demo",
                "workspace_id": "T123",
            },
        )
        assert response_invocation.status == Status.OK
        response_payload = json.loads(response_invocation.body.decode())
        assert response_payload["tenant"]["slug"] == "psi"


@pytest.mark.asyncio
async def test_bootstrap_admin_support_ticket_update_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme",),
        database=db_config,
    )
    app = MereApp(config=config, database=database, bootstrap_enabled=False)

    settings = BootstrapChatOpsSettings(
        enabled=True,
        webhook=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/demo"),
    )
    chatops_control = BootstrapChatOpsControlPlane(
        app,
        settings,
        command_pattern=bootstrap._TENANT_SLUG_PATTERN,
    )

    async def noop_send(self: ChatOpsService, tenant: TenantContext, message: ChatMessage) -> None:
        return None

    monkeypatch.setattr(ChatOpsService, "send", noop_send, raising=False)
    chatops_control.configure(settings)

    ticket = BootstrapSupportTicketRecord(
        tenant_slug="acme",
        kind=SupportTicketKind.ISSUE,
        subject="Login",
        message="Cannot login",
    )
    tenant_ticket = BootstrapTenantSupportTicketRecord(
        admin_ticket_id=ticket.id,
        kind=SupportTicketKind.ISSUE,
        subject=ticket.subject,
        message=ticket.message,
    )

    class AdminSupportStore:
        def __init__(self) -> None:
            self.records: dict[str, BootstrapSupportTicketRecord] = {ticket.id: ticket}

        async def get(
            self, *, filters: Mapping[str, object] | None = None, tenant: TenantContext | None = None
        ) -> BootstrapSupportTicketRecord | None:
            if not filters:
                return None
            ticket_id = cast(str | None, filters.get("id"))
            if ticket_id is None:
                return None
            return self.records.get(ticket_id)

        async def update(
            self,
            *,
            filters: Mapping[str, object],
            values: Mapping[str, object],
        ) -> BootstrapSupportTicketRecord:
            current = self.records[cast(str, filters["id"])]
            updated = structs.replace(current, **values)
            self.records[current.id] = updated
            return updated

    class TenantSupportStore:
        def __init__(self) -> None:
            self.records: dict[str, BootstrapTenantSupportTicketRecord] = {tenant_ticket.admin_ticket_id: tenant_ticket}

        async def get(
            self,
            *,
            tenant: TenantContext,
            filters: Mapping[str, object],
        ) -> BootstrapTenantSupportTicketRecord | None:
            ticket_id = cast(str | None, filters.get("admin_ticket_id"))
            if ticket_id is None:
                return None
            return self.records.get(ticket_id)

        async def update(
            self,
            *,
            tenant: TenantContext,
            filters: Mapping[str, object],
            values: Mapping[str, object],
        ) -> BootstrapTenantSupportTicketRecord:
            current = self.records[cast(str, filters["admin_ticket_id"])]
            updated = structs.replace(current, **values)
            self.records[current.admin_ticket_id] = updated
            return updated

    stub_orm: ORM = cast(
        ORM,
        SimpleNamespace(
            admin=SimpleNamespace(
                support_tickets=AdminSupportStore(),
            ),
            tenants=SimpleNamespace(
                support_tickets=TenantSupportStore(),
            ),
        ),
    )

    tenant_store = cast(TenantSupportStore, stub_orm.tenants.support_tickets)

    async def ensure_contexts(slugs: Iterable[str]) -> None:
        return None

    admin_control = BootstrapAdminControlPlane(
        app,
        slug_normalizer=lambda raw: raw.strip().lower(),
        slug_pattern=bootstrap._TENANT_SLUG_PATTERN,
        ensure_contexts=ensure_contexts,
        chatops=chatops_control,
        sync_allowed_tenants=lambda config: None,
    )

    update_payload = BootstrapSupportTicketUpdateRequest(status="responded", note=" Investigating ")
    updated = await admin_control.update_support_ticket(
        ticket.id,
        update_payload,
        orm=stub_orm,
        actor="agent",
    )

    assert updated.status == SupportTicketStatus.RESPONDED
    assert updated.updates[-1].note == "Investigating"
    tenant_updated = tenant_store.records[ticket.id]
    assert tenant_updated.status == SupportTicketStatus.RESPONDED
    assert tenant_updated.updates[-1].note == "Investigating"

    no_note_payload = BootstrapSupportTicketUpdateRequest(status="responded", note=None)
    updated_no_note = await admin_control.update_support_ticket(
        ticket.id,
        no_note_payload,
        orm=stub_orm,
        actor="agent",
    )
    assert updated_no_note.status == SupportTicketStatus.RESPONDED

    tenant_store.records.pop(ticket.id)
    resolved_payload = BootstrapSupportTicketUpdateRequest(status="resolved", note=None)
    updated_missing = await admin_control.update_support_ticket(
        ticket.id,
        resolved_payload,
        orm=stub_orm,
        actor="agent",
    )
    assert updated_missing.status == SupportTicketStatus.RESOLVED


@pytest.mark.asyncio
async def test_bootstrap_admin_support_ticket_update_sequence_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme",),
        database=db_config,
    )
    app = MereApp(config=config, database=database, bootstrap_enabled=False)

    settings = BootstrapChatOpsSettings(
        enabled=True,
        webhook=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/demo"),
    )
    chatops_control = BootstrapChatOpsControlPlane(
        app,
        settings,
        command_pattern=bootstrap._TENANT_SLUG_PATTERN,
    )

    async def noop_send(self: ChatOpsService, tenant: TenantContext, message: ChatMessage) -> None:
        return None

    monkeypatch.setattr(ChatOpsService, "send", noop_send, raising=False)
    chatops_control.configure(settings)

    ticket = BootstrapSupportTicketRecord(
        tenant_slug="acme",
        kind=SupportTicketKind.ISSUE,
        subject="Login",
        message="Cannot login",
    )

    class ListReturningAdminSupportStore:
        def __init__(self) -> None:
            self.records: dict[str, BootstrapSupportTicketRecord] = {ticket.id: ticket}

        async def get(
            self,
            *,
            filters: Mapping[str, object] | None = None,
            tenant: TenantContext | None = None,
        ) -> BootstrapSupportTicketRecord | None:
            if not filters:
                return None
            ticket_id = cast(str | None, filters.get("id"))
            if ticket_id is None:
                return None
            return self.records.get(ticket_id)

        async def update(
            self,
            *,
            filters: Mapping[str, object],
            values: Mapping[str, object],
        ) -> list[BootstrapSupportTicketRecord]:
            current = self.records[cast(str, filters["id"])]
            updated = structs.replace(current, **values)
            self.records[current.id] = updated
            return [updated]

    tenant_ticket = BootstrapTenantSupportTicketRecord(
        admin_ticket_id=ticket.id,
        kind=SupportTicketKind.ISSUE,
        subject=ticket.subject,
        message=ticket.message,
    )

    class TenantSupportStore:
        def __init__(self) -> None:
            self.records: dict[str, BootstrapTenantSupportTicketRecord] = {tenant_ticket.admin_ticket_id: tenant_ticket}

        async def get(
            self,
            *,
            tenant: TenantContext,
            filters: Mapping[str, object],
        ) -> BootstrapTenantSupportTicketRecord | None:
            ticket_id = cast(str | None, filters.get("admin_ticket_id"))
            if ticket_id is None:
                return None
            return self.records.get(ticket_id)

        async def update(
            self,
            *,
            tenant: TenantContext,
            filters: Mapping[str, object],
            values: Mapping[str, object],
        ) -> BootstrapTenantSupportTicketRecord:
            current = self.records[cast(str, filters["admin_ticket_id"])]
            updated = structs.replace(current, **values)
            self.records[current.admin_ticket_id] = updated
            return updated

    tenant_store = TenantSupportStore()

    stub_orm: ORM = cast(
        ORM,
        SimpleNamespace(
            admin=SimpleNamespace(
                support_tickets=ListReturningAdminSupportStore(),
            ),
            tenants=SimpleNamespace(
                support_tickets=tenant_store,
            ),
        ),
    )

    async def ensure_contexts(slugs: Iterable[str]) -> None:
        return None

    admin_control = BootstrapAdminControlPlane(
        app,
        slug_normalizer=lambda raw: raw.strip().lower(),
        slug_pattern=bootstrap._TENANT_SLUG_PATTERN,
        ensure_contexts=ensure_contexts,
        chatops=chatops_control,
        sync_allowed_tenants=lambda config: None,
    )

    update_payload = BootstrapSupportTicketUpdateRequest(status="responded", note="Investigating")
    updated = await admin_control.update_support_ticket(
        ticket.id,
        update_payload,
        orm=stub_orm,
        actor="agent",
    )

    assert isinstance(updated, BootstrapSupportTicketRecord)
    assert updated.status == SupportTicketStatus.RESPONDED
    tenant_updated = tenant_store.records[ticket.id]
    assert tenant_updated.status == SupportTicketStatus.RESPONDED


@pytest.mark.asyncio
async def test_bootstrap_seeder_persists_config() -> None:
    class RecordingManager:
        def __init__(self) -> None:
            self.deleted: list[tuple[TenantContext | None, object | None]] = []
            self.created: list[tuple[TenantContext | None, object]] = []

        async def delete(self, *, tenant: TenantContext | None = None, filters: object | None = None) -> int:
            self.deleted.append((tenant, filters))
            return 0

        async def create(self, data: object, *, tenant: TenantContext | None = None) -> object:
            self.created.append((tenant, data))
            return data

    class RecordingStateManager:
        def __init__(self) -> None:
            self.created: list[BootstrapSeedStateRecord] = []
            self.updated: list[tuple[Mapping[str, object] | None, Mapping[str, object]]] = []
            self.state: object | None = None

        async def get(
            self,
            *,
            tenant: TenantContext | None = None,
            filters: Mapping[str, object] | None = None,
        ) -> object | None:
            return self.state

        async def create(
            self,
            data: BootstrapSeedStateRecord,
            *,
            tenant: TenantContext | None = None,
        ) -> BootstrapSeedStateRecord:
            self.created.append(data)
            self.state = types.SimpleNamespace(id=data.id, fingerprint=data.fingerprint)
            return data

        async def update(
            self,
            values: Mapping[str, object],
            *,
            tenant: TenantContext | None = None,
            filters: Mapping[str, object] | None = None,
        ) -> list[object]:
            self.updated.append((filters, values))
            if self.state is not None:
                fingerprint = cast(str, values.get("fingerprint", self.state.fingerprint))
                self.state = types.SimpleNamespace(id=self.state.id, fingerprint=fingerprint)
            return []

    admin_users = RecordingManager()
    tenant_records = RecordingManager()
    tenant_users = RecordingManager()
    seed_state = RecordingStateManager()

    orm_stub = types.SimpleNamespace(
        admin=types.SimpleNamespace(
            bootstrap_admin_users=admin_users,
            bootstrap_tenants=tenant_records,
            bootstrap_seed_state=seed_state,
        ),
        tenants=types.SimpleNamespace(bootstrap_users=tenant_users),
    )

    config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="acme",
                name="Acme Rockets",
                users=(
                    BootstrapUser(
                        id="usr_acme_owner",
                        email="founder@acme.test",
                        password="demo-pass",
                        passkeys=(
                            BootstrapPasskey(
                                credential_id="acme-passkey",
                                secret="passkey-secret",
                                label="YubiKey",
                            ),
                        ),
                        mfa_code="654321",
                        sso=BootstrapSsoProvider(
                            slug="okta",
                            kind="saml",
                            display_name="Okta",
                            redirect_url="https://id.acme.test/sso/start",
                        ),
                    ),
                ),
            ),
        ),
        admin=BootstrapAdminRealm(
            users=(
                BootstrapUser(
                    id="adm_root",
                    email="root@admin.test",
                    password="admin-pass",
                    passkeys=(BootstrapPasskey(credential_id="adm-passkey", secret="adm-secret"),),
                    mfa_code="111111",
                ),
            ),
        ),
    )

    tenants_map = {
        tenant.slug: TenantContext(
            tenant=tenant.slug,
            site="demo",
            domain="local.test",
            scope=TenantScope.TENANT,
        )
        for tenant in config.tenants
    }

    seeder = BootstrapSeeder(cast(ORM, orm_stub))
    seeded = await seeder.apply(config, tenants=tenants_map)
    assert seeded is True

    assert len(admin_users.deleted) == 1
    assert len(admin_users.created) == 1
    admin_record = admin_users.created[0][1]
    assert isinstance(admin_record, BootstrapAdminUserRecord)
    assert admin_record.passkeys == (
        BootstrapPasskeyRecord(credential_id="adm-passkey", secret="adm-secret", label=None),
    )

    assert len(tenant_records.deleted) == 1
    assert len(tenant_records.created) == 1
    tenant_record = tenant_records.created[0][1]
    assert isinstance(tenant_record, BootstrapTenantRecord)
    assert tenant_record.slug == "acme"

    assert len(tenant_users.deleted) == 1
    deleted_ctx = tenant_users.deleted[0][0]
    assert isinstance(deleted_ctx, TenantContext)
    assert deleted_ctx.tenant == "acme"

    created_user = tenant_users.created[0][1]
    assert isinstance(created_user, BootstrapTenantUserRecord)
    assert created_user.email == "founder@acme.test"
    assert created_user.passkeys == (
        BootstrapPasskeyRecord(
            credential_id="acme-passkey",
            secret="passkey-secret",
            label="YubiKey",
        ),
    )
    assert created_user.sso_provider is not None

    assert len(seed_state.created) == 1
    created_state = seed_state.created[0]
    assert isinstance(created_state, BootstrapSeedStateRecord)
    assert created_state.key == "bootstrap_auth"
    assert seed_state.updated == []


@pytest.mark.asyncio
async def test_bootstrap_seeder_skips_when_fingerprint_matches() -> None:
    state_manager = types.SimpleNamespace(
        created=[],
        updated=[],
        state=None,
    )

    class SeedStateManager:
        async def get(self, **_: object) -> object | None:
            return state_manager.state

        async def create(self, data: BootstrapSeedStateRecord, **_: object) -> BootstrapSeedStateRecord:
            state_manager.created.append(data)
            state_manager.state = types.SimpleNamespace(id=data.id, fingerprint=data.fingerprint)
            return data

        async def update(self, values: Mapping[str, object], **_: object) -> list[object]:
            state_manager.updated.append(values)
            if state_manager.state is not None:
                fingerprint = cast(str, values.get("fingerprint", state_manager.state.fingerprint))
                state_manager.state = types.SimpleNamespace(id=state_manager.state.id, fingerprint=fingerprint)
            return []

    class RecordingManager:
        def __init__(self) -> None:
            self.deleted: list[tuple[TenantContext | None, object | None]] = []
            self.created: list[tuple[TenantContext | None, object]] = []

        async def delete(self, *, tenant: TenantContext | None = None, filters: object | None = None) -> int:
            self.deleted.append((tenant, filters))
            return 0

        async def create(self, data: object, *, tenant: TenantContext | None = None) -> object:
            self.created.append((tenant, data))
            return data

    admin_manager = RecordingManager()
    tenant_manager = RecordingManager()
    tenant_users = RecordingManager()
    seed_manager = SeedStateManager()

    orm_stub = types.SimpleNamespace(
        admin=types.SimpleNamespace(
            bootstrap_admin_users=admin_manager,
            bootstrap_tenants=tenant_manager,
            bootstrap_seed_state=seed_manager,
        ),
        tenants=types.SimpleNamespace(bootstrap_users=tenant_users),
    )

    tenant = BootstrapTenant(
        slug="acme",
        name="Acme",
        users=(
            BootstrapUser(
                id="usr_acme",
                email="founder@acme.test",
                password="demo-pass",
            ),
        ),
    )
    config = BootstrapAuthConfig(tenants=(tenant,), admin=DEFAULT_BOOTSTRAP_AUTH.admin)
    context = TenantContext(tenant="acme", site="demo", domain="local.test", scope=TenantScope.TENANT)
    seeder = BootstrapSeeder(cast(ORM, orm_stub))

    first = await seeder.apply(config, tenants={"acme": context})
    assert first is True
    assert len(admin_manager.deleted) == 1
    assert len(state_manager.created) == 1

    second = await seeder.apply(config, tenants={"acme": context})
    assert second is False
    assert len(admin_manager.deleted) == 1
    assert state_manager.state is not None
    assert state_manager.updated == []

    updated_config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="acme",
                name="Acme",
                users=(
                    BootstrapUser(
                        id="usr_acme",
                        email="founder@acme.test",
                        password="new-pass",
                    ),
                ),
            ),
        ),
        admin=DEFAULT_BOOTSTRAP_AUTH.admin,
    )
    third = await seeder.apply(updated_config, tenants={"acme": context})
    assert third is True
    assert len(admin_manager.deleted) == 2
    assert state_manager.updated


@pytest.mark.asyncio
async def test_bootstrap_repository_roundtrip() -> None:
    tenant_record = BootstrapTenantRecord(id="tnt_acme", slug="acme", name="Acme")
    tenant_user = BootstrapTenantUserRecord(
        id="usr_acme",
        email="founder@acme.test",
        password="demo-pass",
        passkeys=(
            BootstrapPasskeyRecord(
                credential_id="acme-passkey",
                secret="passkey-secret",
                label="Primary",
            ),
        ),
        mfa_code="654321",
        sso_provider=BootstrapSsoProvider(
            slug="okta",
            kind="saml",
            display_name="Okta",
            redirect_url="https://id.acme.test/sso/start",
        ),
    )
    admin_user = BootstrapAdminUserRecord(
        id="adm_root",
        email="root@admin.test",
        password="admin-pass",
        passkeys=(BootstrapPasskeyRecord(credential_id="adm-passkey", secret="adm-secret", label=None),),
        mfa_code="111111",
    )

    class ListManager:
        def __init__(self, items: list[object]) -> None:
            self._items = items

        async def list(self, **_: object) -> list[object]:
            return list(self._items)

    class TenantUserManager:
        def __init__(self, mapping: dict[str, list[BootstrapTenantUserRecord]]) -> None:
            self._mapping = mapping

        async def list(self, *, tenant: TenantContext, **_: object) -> list[BootstrapTenantUserRecord]:
            return list(self._mapping.get(tenant.tenant, []))

    orm_stub = types.SimpleNamespace(
        admin=types.SimpleNamespace(
            bootstrap_tenants=ListManager([tenant_record]),
            bootstrap_admin_users=ListManager([admin_user]),
        ),
        tenants=types.SimpleNamespace(
            bootstrap_users=TenantUserManager({"acme": [tenant_user]}),
        ),
    )

    repository = BootstrapRepository(cast(ORM, orm_stub), site="demo", domain="local.test")
    config = await repository.load()
    assert config is not None
    assert config.tenants[0].slug == "acme"
    assert config.tenants[0].users[0].passkeys[0].secret == "passkey-secret"
    assert config.admin.users[0].email == "root@admin.test"


@pytest.mark.asyncio
async def test_attach_bootstrap_bootstraps_database(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class StubSeeder:
        def __init__(self, orm: ORM) -> None:
            calls["seeder_init"] = orm

        async def apply(self, config: BootstrapAuthConfig, *, tenants: Mapping[str, TenantContext]) -> bool:
            calls["seed_config"] = config
            calls["seed_tenants"] = sorted(tenants)
            return True

    class StubRepository:
        def __init__(self, orm: ORM, *, site: str, domain: str) -> None:
            calls["repository_init"] = (orm, site, domain)

        async def load(self) -> BootstrapAuthConfig | None:
            calls["repository_load"] = True
            return None

    async def fake_ensure(database: Database, tenants: Sequence[TenantContext]) -> None:
        calls.setdefault("schemas", []).append([ctx.tenant for ctx in tenants])

    async def fake_run_all(
        self: MigrationRunner,
        *,
        scope=None,
        tenants: Sequence[TenantContext] | None = None,
        background=None,
    ) -> list[str]:
        calls.setdefault("migrations", []).append([ctx.tenant for ctx in tenants or []])
        return []

    original_reload = bootstrap.BootstrapAuthEngine.reload

    async def recording_reload(self: BootstrapAuthEngine, config: BootstrapAuthConfig) -> None:
        calls["reload_config"] = config
        await original_reload(self, config)

    monkeypatch.setattr(bootstrap, "BootstrapSeeder", StubSeeder)
    monkeypatch.setattr(bootstrap, "BootstrapRepository", StubRepository)
    monkeypatch.setattr(bootstrap, "ensure_tenant_schemas", fake_ensure)
    monkeypatch.setattr(MigrationRunner, "run_all", fake_run_all)
    monkeypatch.setattr(bootstrap.BootstrapAuthEngine, "reload", recording_reload)

    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme", "beta"),
        database=db_config,
    )
    database = Database(db_config, pool=pool)
    orm = ORM(database)
    app = MereApp(config, database=database, orm=orm, bootstrap_enabled=False)
    attach_bootstrap(app)

    async with TestClient(app) as client:
        response = await client.get("/__mere/ping", tenant="acme")
        assert response.status == 200

    assert calls["seed_config"] is DEFAULT_BOOTSTRAP_AUTH
    assert sorted(calls["seed_tenants"]) == ["acme", "beta"]
    assert calls["repository_load"] is True
    assert calls["reload_config"] is DEFAULT_BOOTSTRAP_AUTH
    assert [sorted(entry) for entry in calls.get("schemas", [])]
    assert [sorted(entry) for entry in calls.get("migrations", [])]


@pytest.mark.asyncio
async def test_ensure_tenant_schemas_handles_empty() -> None:
    pool = FakePool()
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    await ensure_tenant_schemas(database, [])
    assert all("CREATE SCHEMA" not in sql for _, sql, *_ in pool.connection.calls)


@pytest.mark.asyncio
async def test_bootstrap_seeder_requires_context() -> None:
    class AsyncNoop:
        async def delete(self, **_: object) -> int:
            return 0

        async def create(self, *args: object, **kwargs: object) -> None:
            return None

    class SeedState:
        async def get(self, **_: object) -> None:
            return None

        async def create(self, *args: object, **kwargs: object) -> None:
            return None

        async def update(self, *args: object, **kwargs: object) -> list[object]:
            return []

    orm_stub = types.SimpleNamespace(
        admin=types.SimpleNamespace(
            bootstrap_admin_users=AsyncNoop(),
            bootstrap_tenants=AsyncNoop(),
            bootstrap_seed_state=SeedState(),
        ),
        tenants=types.SimpleNamespace(bootstrap_users=AsyncNoop()),
    )
    config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="acme",
                name="Acme",
                users=(BootstrapUser(id="usr", email="founder@acme.test"),),
            ),
        ),
        admin=BootstrapAdminRealm(users=()),
    )
    seeder = BootstrapSeeder(cast(ORM, orm_stub))
    with pytest.raises(RuntimeError):
        await seeder.apply(config, tenants={})


@pytest.mark.asyncio
async def test_attach_bootstrap_syncs_allowed_tenants_from_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    class StubSeeder:
        def __init__(self, orm: ORM) -> None:
            self.orm = orm

        async def apply(self, config: BootstrapAuthConfig, *, tenants: Mapping[str, TenantContext]) -> bool:
            return True

    class StubRepository:
        def __init__(self, orm: ORM, *, site: str, domain: str) -> None:
            self.orm = orm
            self.site = site
            self.domain = domain

        async def load(self) -> BootstrapAuthConfig | None:
            return BootstrapAuthConfig(
                tenants=(
                    BootstrapTenant(
                        slug="gamma",
                        name="Gamma Corp",
                        users=(
                            BootstrapUser(
                                id="usr_gamma_owner",
                                email="owner@gamma.test",
                                password="gamma-pass",
                            ),
                        ),
                    ),
                ),
                admin=DEFAULT_BOOTSTRAP_AUTH.admin,
            )

    async def fake_ensure(database: Database, tenants: Sequence[TenantContext]) -> None:
        return None

    async def fake_run_all(
        self: MigrationRunner,
        *,
        scope=None,
        tenants: Sequence[TenantContext] | None = None,
        background=None,
    ) -> list[str]:
        return []

    monkeypatch.setattr(bootstrap, "BootstrapSeeder", StubSeeder)
    monkeypatch.setattr(bootstrap, "BootstrapRepository", StubRepository)
    monkeypatch.setattr(bootstrap, "ensure_tenant_schemas", fake_ensure)
    monkeypatch.setattr(MigrationRunner, "run_all", fake_run_all)

    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    app_config = AppConfig(site="demo", domain="local.test", allowed_tenants=(), database=db_config)
    database = Database(db_config, pool=pool)
    orm = ORM(database)
    app = MereApp(app_config, database=database, orm=orm, bootstrap_enabled=False)

    attach_bootstrap(app)

    assert "gamma" not in app.tenant_resolver.allowed_tenants

    async with TestClient(app) as client:
        response = await client.get("/__mere/ping", tenant="gamma")
        assert response.status == 200

    assert "gamma" in app.tenant_resolver.allowed_tenants


@pytest.mark.asyncio
async def test_bootstrap_repository_returns_none_when_empty() -> None:
    class ListManager:
        def __init__(self) -> None:
            self._items: list[object] = []

        async def list(self, **_: object) -> list[object]:
            return []

    orm_stub = types.SimpleNamespace(
        admin=types.SimpleNamespace(
            bootstrap_tenants=ListManager(),
            bootstrap_admin_users=ListManager(),
        ),
        tenants=types.SimpleNamespace(bootstrap_users=types.SimpleNamespace(list=lambda **_: [])),
    )
    repository = BootstrapRepository(cast(ORM, orm_stub), site="demo", domain="local.test")
    assert await repository.load() is None


@pytest.mark.asyncio
async def test_attach_bootstrap_with_custom_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class StubSeeder:
        def __init__(self, orm: ORM) -> None:
            calls["init"] = orm

        async def apply(self, config: BootstrapAuthConfig, *, tenants: Mapping[str, TenantContext]) -> bool:
            calls["config"] = config
            calls["tenants"] = sorted(tenants)
            return True

    async def fake_ensure(database: Database, tenants: Sequence[TenantContext]) -> None:
        calls.setdefault("ensure", []).append([ctx.tenant for ctx in tenants])

    async def fake_run_all(
        self: MigrationRunner,
        *,
        scope=None,
        tenants: Sequence[TenantContext] | None = None,
        background=None,
    ) -> list[str]:
        calls.setdefault("run_all", []).append([ctx.tenant for ctx in tenants or []])
        return []

    async def recording_reload(self: BootstrapAuthEngine, config: BootstrapAuthConfig) -> None:
        calls["reload"] = config
        await original_reload(self, config)

    original_reload = bootstrap.BootstrapAuthEngine.reload
    monkeypatch.setattr(bootstrap, "BootstrapSeeder", StubSeeder)
    monkeypatch.setattr(bootstrap, "ensure_tenant_schemas", fake_ensure)
    monkeypatch.setattr(MigrationRunner, "run_all", fake_run_all)
    monkeypatch.setattr(bootstrap.BootstrapAuthEngine, "reload", recording_reload)

    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme",),
        database=db_config,
    )
    database = Database(db_config, pool=pool)
    orm = ORM(database)
    app = MereApp(config, database=database, orm=orm, bootstrap_enabled=False)
    custom = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="acme",
                name="Acme",
                users=(BootstrapUser(id="usr", email="owner@acme.test"),),
            ),
        ),
        admin=BootstrapAdminRealm(users=()),
    )
    attach_bootstrap(app, auth_config=custom)

    async with TestClient(app) as client:
        response = await client.get("/__mere/ping", tenant="acme")
        assert response.status == 200

    assert calls["config"] is custom
    assert calls["reload"] is custom


def test_load_bootstrap_auth_from_env_json() -> None:
    payload = {
        "tenants": [
            {
                "slug": "env",
                "name": "Env Corp",
                "users": [
                    {
                        "id": "usr_env",
                        "email": "owner@env.test",
                        "password": "secret",
                    }
                ],
            }
        ],
        "admin": {
            "users": [
                {
                    "id": "adm_env",
                    "email": "admin@env.test",
                    "password": "admin-secret",
                }
            ]
        },
    }
    env = {"MERE_BOOTSTRAP_AUTH": json.dumps(payload)}
    loaded = load_bootstrap_auth_from_env(env=env)
    assert loaded is not None
    assert loaded.tenants[0].slug == "env"
    assert loaded.admin.users[0].email == "admin@env.test"


def test_load_bootstrap_auth_from_env_file(tmp_path: Path) -> None:
    payload = {
        "tenants": [
            {
                "slug": "file",
                "name": "File Inc",
                "users": [
                    {
                        "id": "usr_file",
                        "email": "owner@file.test",
                        "password": "secret",
                    }
                ],
            }
        ],
        "admin": {
            "users": [
                {
                    "id": "adm_file",
                    "email": "admin@file.test",
                    "password": "admin-secret",
                }
            ]
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload))
    env = {"MERE_BOOTSTRAP_AUTH_FILE": str(path)}
    loaded = load_bootstrap_auth_from_env(env=env)
    assert loaded is not None
    assert loaded.tenants[0].slug == "file"
    assert loaded.admin.users[0].email == "admin@file.test"


def test_load_bootstrap_auth_from_env_invalid() -> None:
    env = {"MERE_BOOTSTRAP_AUTH": "{not json}"}
    with pytest.raises(RuntimeError):
        load_bootstrap_auth_from_env(env=env)


@pytest.mark.asyncio
async def test_attach_bootstrap_uses_repository_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class StubSeeder:
        def __init__(self, orm: ORM) -> None:
            calls["seeder_init"] = orm

        async def apply(self, config: BootstrapAuthConfig, *, tenants: Mapping[str, TenantContext]) -> bool:
            calls.setdefault("seed", []).append(sorted(tenants))
            return True

    class StubRepository:
        def __init__(self, orm: ORM, *, site: str, domain: str) -> None:
            self._orm = orm
            self._site = site
            self._domain = domain

        async def load(self) -> BootstrapAuthConfig | None:
            return BootstrapAuthConfig(
                tenants=(
                    BootstrapTenant(
                        slug="gamma",
                        name="Gamma",
                        users=(BootstrapUser(id="usr", email="owner@gamma.test"),),
                    ),
                ),
                admin=BootstrapAdminRealm(users=()),
            )

    async def fake_ensure(database: Database, tenants: Sequence[TenantContext]) -> None:
        calls.setdefault("schemas", []).append([ctx.tenant for ctx in tenants])

    async def fake_run_all(
        self: MigrationRunner,
        *,
        scope=None,
        tenants: Sequence[TenantContext] | None = None,
        background=None,
    ) -> list[str]:
        calls.setdefault("runs", []).append([ctx.tenant for ctx in tenants or []])
        return []

    async def recording_reload(self: BootstrapAuthEngine, config: BootstrapAuthConfig) -> None:
        calls["reload"] = config
        await original_reload(self, config)

    original_reload = bootstrap.BootstrapAuthEngine.reload
    monkeypatch.setattr(bootstrap, "BootstrapSeeder", StubSeeder)
    monkeypatch.setattr(bootstrap, "BootstrapRepository", StubRepository)
    monkeypatch.setattr(bootstrap, "ensure_tenant_schemas", fake_ensure)
    monkeypatch.setattr(MigrationRunner, "run_all", fake_run_all)
    monkeypatch.setattr(bootstrap.BootstrapAuthEngine, "reload", recording_reload)

    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme",),
        database=db_config,
    )
    database = Database(db_config, pool=pool)
    orm = ORM(database)
    app = MereApp(config, database=database, orm=orm, bootstrap_enabled=False)
    attach_bootstrap(app)

    async with TestClient(app) as client:
        response = await client.get("/__mere/ping", tenant="acme")
        assert response.status == 200

    reload_config = calls["reload"]
    assert isinstance(reload_config, BootstrapAuthConfig)
    assert reload_config.tenants[0].slug == "gamma"
    assert any("gamma" in entry for entry in calls.get("schemas", []))


# ------------------------------------------------------------------------------------------- engine unit tests


def _tenant(site: str, domain: str, slug: str, scope: TenantScope) -> TenantContext:
    return TenantContext(tenant=slug, site=site, domain=domain, scope=scope)


@pytest.mark.asyncio
async def test_bootstrap_engine_rejects_public_scope() -> None:
    engine = BootstrapAuthEngine(DEFAULT_BOOTSTRAP_AUTH)
    tenant = _tenant("demo", "local.test", "public", TenantScope.PUBLIC)
    with pytest.raises(HTTPError) as exc:
        await engine.start(tenant, email="user@example.com")
    _assert_error_detail(exc, "login_not_available")


@pytest.mark.asyncio
async def test_bootstrap_engine_unknown_user_and_authenticators() -> None:
    engine = BootstrapAuthEngine(DEFAULT_BOOTSTRAP_AUTH)
    tenant = _tenant("demo", "local.test", "acme", TenantScope.TENANT)
    with pytest.raises(HTTPError) as exc:
        await engine.start(tenant, email="missing@acme.test")
    _assert_error_detail(exc, "unknown_user")

    config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="gamma",
                name="Gamma",
                users=(BootstrapUser(id="usr_gamma", email="ops@gamma.test"),),
            ),
        ),
        admin=DEFAULT_BOOTSTRAP_AUTH.admin,
    )
    engine = BootstrapAuthEngine(config)
    tenant = _tenant("demo", "local.test", "gamma", TenantScope.TENANT)
    with pytest.raises(HTTPError) as exc:
        await engine.start(tenant, email="ops@gamma.test")
    _assert_error_detail(exc, "no_authenticators")


@pytest.mark.asyncio
async def test_bootstrap_engine_passkey_error_paths() -> None:
    engine = BootstrapAuthEngine(DEFAULT_BOOTSTRAP_AUTH)
    beta = _tenant("demo", "local.test", "beta", TenantScope.TENANT)

    start = await engine.start(beta, email="ops@beta.test")
    with pytest.raises(HTTPError) as exc:
        await engine.passkey(beta, PasskeyAttempt(flow_token=start.flow_token, credential_id="bogus", signature="x"))
    _assert_error_detail(exc, "unknown_passkey")

    start = await engine.start(beta, email="ops@beta.test")
    engine._flows[start.flow_token].challenge = None
    with pytest.raises(HTTPError) as exc:
        await engine.passkey(
            beta,
            PasskeyAttempt(
                flow_token=start.flow_token,
                credential_id="beta-passkey",
                signature="ignored",
            ),
        )
    _assert_error_detail(exc, "missing_challenge")

    start = await engine.start(beta, email="ops@beta.test")
    with pytest.raises(HTTPError) as exc:
        await engine.passkey(
            beta,
            PasskeyAttempt(
                flow_token=start.flow_token,
                credential_id="beta-passkey",
                signature="invalid",
            ),
        )
    _assert_error_detail(exc, "invalid_passkey")

    engine = BootstrapAuthEngine(DEFAULT_BOOTSTRAP_AUTH)
    admin = _tenant("demo", "local.test", "admin", TenantScope.ADMIN)
    start = await engine.start(admin, email="root@admin.test")
    with pytest.raises(HTTPError) as exc:
        await engine.passkey(
            admin,
            PasskeyAttempt(flow_token=start.flow_token, credential_id="beta-passkey", signature="sig"),
        )
    _assert_error_detail(exc, "passkey_not_expected")

    config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="zeta",
                name="Zeta",
                users=(
                    BootstrapUser(
                        id="usr_zeta",
                        email="ops@zeta.test",
                        password="zeta-password",
                        sso=BootstrapSsoProvider(
                            slug="okta",
                            kind="saml",
                            display_name="Okta",
                            redirect_url="https://id.zeta.test/start",
                        ),
                    ),
                ),
            ),
        ),
        admin=DEFAULT_BOOTSTRAP_AUTH.admin,
    )
    engine = BootstrapAuthEngine(config)
    zeta = _tenant("demo", "local.test", "zeta", TenantScope.TENANT)
    start = await engine.start(zeta, email="ops@zeta.test")
    assert start.next is LoginStep.SSO
    assert start.fallback is LoginStep.PASSWORD
    with pytest.raises(HTTPError) as exc:
        await engine.passkey(
            zeta,
            PasskeyAttempt(flow_token=start.flow_token, credential_id="ignored", signature="sig"),
        )
    _assert_error_detail(exc, "passkey_not_available")


@pytest.mark.asyncio
async def test_bootstrap_engine_password_paths() -> None:
    engine = BootstrapAuthEngine(DEFAULT_BOOTSTRAP_AUTH)
    beta = _tenant("demo", "local.test", "beta", TenantScope.TENANT)

    # Password fallback from passkey
    start = await engine.start(beta, email="ops@beta.test")
    response = await engine.password(beta, PasswordAttempt(flow_token=start.flow_token, password="beta-password"))
    assert response.next is LoginStep.MFA

    # Invalid password
    start = await engine.start(beta, email="ops@beta.test")
    with pytest.raises(HTTPError) as exc:
        await engine.password(beta, PasswordAttempt(flow_token=start.flow_token, password="wrong"))
    _assert_error_detail(exc, "invalid_password")

    # Password not expected once MFA started
    start = await engine.start(beta, email="ops@beta.test")
    user = DEFAULT_BOOTSTRAP_AUTH.tenants[1].users[0]
    passkey_cfg = user.passkeys[0]
    manager = PasskeyManager()
    demo_passkey = manager.register(
        user_id=user.id,
        credential_id=passkey_cfg.credential_id,
        secret=passkey_cfg.secret.encode("utf-8"),
        user_handle="demo",
    )
    challenge = engine._flows[start.flow_token].challenge
    assert challenge is not None
    signature = manager.sign(passkey=demo_passkey, challenge=challenge)
    await engine.passkey(
        beta,
        PasskeyAttempt(
            flow_token=start.flow_token,
            credential_id=passkey_cfg.credential_id,
            signature=signature,
        ),
    )
    with pytest.raises(HTTPError) as exc:
        await engine.password(beta, PasswordAttempt(flow_token=start.flow_token, password="beta-password"))
    _assert_error_detail(exc, "password_not_expected")

    # Password not available when no fallback defined
    config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="gamma",
                name="Gamma",
                users=(
                    BootstrapUser(
                        id="usr_gamma",
                        email="ops@gamma.test",
                        passkeys=(BootstrapPasskey(credential_id="gamma-passkey", secret="gamma-secret"),),
                    ),
                ),
            ),
        ),
        admin=DEFAULT_BOOTSTRAP_AUTH.admin,
    )
    engine = BootstrapAuthEngine(config)
    gamma = _tenant("demo", "local.test", "gamma", TenantScope.TENANT)
    start = await engine.start(gamma, email="ops@gamma.test")
    with pytest.raises(HTTPError) as exc:
        await engine.password(gamma, PasswordAttempt(flow_token=start.flow_token, password="irrelevant"))
    _assert_error_detail(exc, "password_not_available")


@pytest.mark.asyncio
async def test_bootstrap_engine_mfa_paths() -> None:
    engine = BootstrapAuthEngine(DEFAULT_BOOTSTRAP_AUTH)
    admin_ctx = _tenant("demo", "local.test", "admin", TenantScope.ADMIN)

    start = await engine.start(admin_ctx, email="root@admin.test")
    with pytest.raises(HTTPError) as exc:
        await engine.mfa(admin_ctx, MfaAttempt(flow_token=start.flow_token, code="000000"))
    _assert_error_detail(exc, "mfa_not_expected")

    await engine.password(admin_ctx, PasswordAttempt(flow_token=start.flow_token, password="admin-password"))
    flow = engine._flows[start.flow_token]
    flow.level = None
    with pytest.raises(HTTPError) as exc:
        await engine.mfa(admin_ctx, MfaAttempt(flow_token=start.flow_token, code="123456"))
    _assert_error_detail(exc, "primary_not_verified")

    flow.level = SessionLevel.PASSWORD_ONLY
    with pytest.raises(HTTPError) as exc:
        await engine.mfa(admin_ctx, MfaAttempt(flow_token=start.flow_token, code="000000"))
    _assert_error_detail(exc, "invalid_mfa")

    flow.level = SessionLevel.PASSWORD_ONLY
    success = await engine.mfa(admin_ctx, MfaAttempt(flow_token=start.flow_token, code="123456"))
    assert success.next is LoginStep.SUCCESS


@pytest.mark.asyncio
async def test_bootstrap_engine_success_and_cleanup_paths() -> None:
    config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="delta",
                name="Delta",
                users=(
                    BootstrapUser(
                        id="usr_delta",
                        email="ops@delta.test",
                        password="delta-pass",
                        passkeys=(BootstrapPasskey(credential_id="delta-passkey", secret="delta-secret"),),
                    ),
                ),
            ),
        ),
        admin=BootstrapAdminRealm(
            users=(
                BootstrapUser(
                    id="adm_demo",
                    email="admin@demo.test",
                    password="demo-admin",
                    passkeys=(BootstrapPasskey(credential_id="adm-passkey", secret="adm-secret"),),
                ),
            ),
        ),
    )
    engine = BootstrapAuthEngine(config)
    delta = _tenant("demo", "local.test", "delta", TenantScope.TENANT)

    start = await engine.start(delta, email="ops@delta.test")
    manager = PasskeyManager()
    passkey = manager.register(
        user_id="usr_delta",
        credential_id="delta-passkey",
        secret=b"delta-secret",
        user_handle="demo",
    )
    flow = engine._flows[start.flow_token]
    assert flow.challenge is not None
    signature = manager.sign(passkey=passkey, challenge=flow.challenge)
    response = await engine.passkey(
        delta,
        PasskeyAttempt(flow_token=start.flow_token, credential_id="delta-passkey", signature=signature),
    )
    assert response.next is LoginStep.SUCCESS

    with pytest.raises(HTTPError) as exc:
        await engine.passkey(
            delta,
            PasskeyAttempt(flow_token=start.flow_token, credential_id="delta-passkey", signature=signature),
        )
    _assert_error_detail(exc, "unknown_flow")

    # Directly exercise flow_completed guard
    with pytest.raises(HTTPError) as exc:
        engine._render_flow(flow)
    _assert_error_detail(exc, "flow_completed")

    # Ensure admin passkeys populate index
    admin_ctx = _tenant("demo", "local.test", "admin", TenantScope.ADMIN)
    start = await engine.start(admin_ctx, email="admin@demo.test")
    with pytest.raises(HTTPError) as exc:
        await engine.passkey(
            admin_ctx,
            PasskeyAttempt(flow_token=start.flow_token, credential_id="adm-passkey", signature="bad"),
        )
    _assert_error_detail(exc, "invalid_passkey")


@pytest.mark.asyncio
async def test_bootstrap_engine_sso_fallback_to_passkey() -> None:
    config = BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(
                slug="epsilon",
                name="Epsilon",
                users=(
                    BootstrapUser(
                        id="usr_epsilon",
                        email="ops@epsilon.test",
                        passkeys=(BootstrapPasskey(credential_id="epsilon-passkey", secret="epsilon-secret"),),
                        sso=BootstrapSsoProvider(
                            slug="okta",
                            kind="saml",
                            display_name="Okta",
                            redirect_url="https://id.epsilon.test/start",
                        ),
                    ),
                ),
            ),
        ),
        admin=DEFAULT_BOOTSTRAP_AUTH.admin,
    )
    engine = BootstrapAuthEngine(config)
    epsilon = _tenant("demo", "local.test", "epsilon", TenantScope.TENANT)
    start = await engine.start(epsilon, email="ops@epsilon.test")
    assert start.next is LoginStep.SSO
    assert start.fallback is LoginStep.PASSKEY
    flow = engine._flows[start.flow_token]
    assert flow.challenge is None

    prompt = await engine.passkey(
        epsilon,
        PasskeyAttempt(flow_token=start.flow_token, credential_id="unused", signature="request"),
    )
    assert prompt.next is LoginStep.PASSKEY
    assert prompt.challenge is not None
    assert prompt.fallback is None

    manager = PasskeyManager()
    user = config.tenants[0].users[0]
    passkey_config = user.passkeys[0]
    passkey = manager.register(
        user_id=user.id,
        credential_id=passkey_config.credential_id,
        secret=passkey_config.secret.encode("utf-8"),
        user_handle="demo",  # value unused by manager
    )
    signature = manager.sign(passkey=passkey, challenge=prompt.challenge)
    success = await engine.passkey(
        epsilon,
        PasskeyAttempt(
            flow_token=start.flow_token,
            credential_id=passkey_config.credential_id,
            signature=signature,
        ),
    )
    assert success.next is LoginStep.SUCCESS


def test_chatops_command_registry_lookup_paths() -> None:
    registry = ChatOpsCommandRegistry()

    async def handler(_: ChatOpsCommandContext) -> dict[str, str]:
        return {"status": "ok"}

    command = ChatOpsSlashCommand(name="demo", description="Demo handler")
    binding = ChatOpsCommandBinding(command=command, handler=handler, name="demo.binding")
    registry.register(binding)

    assert registry.bindings() == (binding,)
    assert registry.commands() == (command,)
    assert registry.binding_by_name("demo.binding") is binding

    with pytest.raises(LookupError):
        registry.binding_by_name("unknown.binding")

    assert registry.binding_for(command) is binding
    equivalent = ChatOpsSlashCommand(name="demo", description="Demo handler")
    assert registry.binding_for(equivalent) is binding

    with pytest.raises(LookupError):
        registry.binding_for(ChatOpsSlashCommand(name="other", description="Other handler"))


@pytest.mark.asyncio
async def test_bootstrap_chatops_control_plane_validation_paths() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme", "beta"),
        database=db_config,
    )
    app = MereApp(config=config, database=database, bootstrap_enabled=False)

    notifications = bootstrap.BootstrapChatOpsNotificationChannels(
        tenant_created="#tenants",
        billing_updated="#billing",
        subscription_past_due="#pastdue",
        trial_extended="#trials",
        support_ticket_created="#support",
        support_ticket_updated="#support",
    )
    commands = (
        BootstrapSlashCommand(
            name="create-tenant",
            action="create_tenant",
            description="Provision tenants",
            aliases=("Bootstrap-Create-Tenant", "create-tenant"),
        ),
        BootstrapSlashCommand(
            name="extend-trial",
            action="extend_trial",
            description="Extend tenant trial periods",
        ),
    )
    settings = BootstrapChatOpsSettings(
        enabled=True,
        webhook=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/demo"),
        notifications=notifications,
        slash_commands=commands,
        bot_user_id="U999",
        admin_workspace="T123",
    )
    control = BootstrapChatOpsControlPlane(
        app,
        settings,
        command_pattern=bootstrap._TENANT_SLUG_PATTERN,
    )

    @app.chatops_command(
        ChatOpsSlashCommand(
            name="create-tenant",
            description="Create tenant via ChatOps",
            visibility="admin",
        ),
        name="bootstrap.chatops.create_tenant",
    )
    async def _create_tenant_handler(context: ChatOpsCommandContext) -> dict[str, str]:
        return {"status": "ok", "slug": context.args.get("slug", "")}

    control.register_action_binding("create_tenant", "bootstrap.chatops.create_tenant")
    control.register_action_binding("extend_trial", "missing.binding")

    control.configure(settings)

    assert control.settings.bot_user_id == "U999"
    assert control.settings.slash_commands[0].aliases == ("bootstrap-create-tenant",)

    with pytest.raises(HTTPError) as invalid_name:
        control.normalize_command_definition(
            BootstrapSlashCommand(
                name="Invalid Name",
                action="create_tenant",
                description="bad",
            )
        )
    _assert_error_detail(invalid_name, "invalid_command_name")

    with pytest.raises(HTTPError) as invalid_alias:
        control.normalize_command_definition(
            BootstrapSlashCommand(
                name="valid-alias",
                action="create_tenant",
                description="bad alias",
                aliases=("invalid alias",),
            )
        )
    _assert_error_detail(invalid_alias, "invalid_command_name")

    with pytest.raises(HTTPError) as duplicate:
        control.normalize_commands(
            (
                BootstrapSlashCommand(
                    name="alpha",
                    action="create_tenant",
                    description="demo",
                    aliases=("dupe",),
                ),
                BootstrapSlashCommand(
                    name="beta",
                    action="extend_trial",
                    description="demo",
                    aliases=("dupe",),
                ),
            )
        )
    _assert_error_detail(duplicate, "duplicate_command")

    admin_context = app.tenant_resolver.context_for(app.config.admin_subdomain, TenantScope.ADMIN)
    request = Request(method="POST", path="/__mere/chatops/slash", tenant=admin_context)

    payload_create = BootstrapSlashCommandInvocation(
        text="<@U999> create-tenant slug=nu name=Nu",
        user_id="U123",
        user_name=None,
        workspace_id="T123",
    )
    binding, args, actor = control.resolve_invocation(request, payload_create)
    assert args["slug"] == "nu"
    assert actor == "U123"
    assert control.action_for_binding(binding) == "create_tenant"

    payload_missing_binding = BootstrapSlashCommandInvocation(
        text="<@U999> extend-trial days=3",
        user_id="U123",
        user_name="demo",
        workspace_id="T123",
    )
    with pytest.raises(ChatOpsCommandResolutionError) as missing_binding_exc:
        control.resolve_invocation(request, payload_missing_binding)
    assert isinstance(missing_binding_exc.value, ChatOpsCommandResolutionError)
    assert missing_binding_exc.value.code == "unknown_command"

    control.configure(
        BootstrapChatOpsSettings(
            enabled=True,
            webhook=settings.webhook,
            notifications=settings.notifications,
            slash_commands=(
                *control.settings.slash_commands,
                BootstrapSlashCommand(
                    name="tenant-metrics",
                    action="tenant_metrics",
                    description="Metrics overview",
                ),
            ),
            bot_user_id="U999",
            admin_workspace="T123",
        )
    )
    payload_repeat = BootstrapSlashCommandInvocation(
        text="<@U999> create-tenant slug=omicron name=Omicron",
        user_id="U456",
        user_name="demo",
        workspace_id="T123",
    )
    binding_repeat, repeat_args, repeat_actor = control.resolve_invocation(request, payload_repeat)
    assert repeat_args["slug"] == "omicron"
    assert repeat_actor == "demo"
    assert control.action_for_binding(binding_repeat) == "create_tenant"

    filtered = control.serialize_settings()
    assert any(cmd["visibility"] == "admin" for cmd in filtered["slash_commands"])

    control.configure(
        BootstrapChatOpsSettings(
            enabled=True,
            webhook=settings.webhook,
            notifications=settings.notifications,
            slash_commands=control.settings.slash_commands,
            bot_user_id="U999",
            admin_workspace=None,
        )
    )
    filtered_without_admin = control.serialize_settings()
    assert all(cmd["visibility"] != "admin" for cmd in filtered_without_admin["slash_commands"])


@pytest.mark.asyncio
async def test_bootstrap_admin_control_plane_support_and_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme", "beta"),
        database=db_config,
    )
    app = MereApp(config=config, database=database, bootstrap_enabled=False)

    notifications = bootstrap.BootstrapChatOpsNotificationChannels(
        tenant_created="#tenants",
        billing_updated="#billing",
        subscription_past_due="#pastdue",
        trial_extended="#trials",
        support_ticket_created="#support",
        support_ticket_updated="#support",
    )
    settings = BootstrapChatOpsSettings(
        enabled=True,
        webhook=SlackWebhookConfig(webhook_url="https://hooks.slack.com/services/demo"),
        notifications=notifications,
    )
    control = BootstrapChatOpsControlPlane(
        app,
        settings,
        command_pattern=bootstrap._TENANT_SLUG_PATTERN,
    )

    events: list[tuple[TenantContext, ChatMessage]] = []

    async def record_send(self: ChatOpsService, tenant: TenantContext, message: ChatMessage) -> None:
        events.append((tenant, message))

    monkeypatch.setattr(ChatOpsService, "send", record_send, raising=False)
    control.configure(settings)

    class StubAuthEngine:
        def __init__(self) -> None:
            self.config = BootstrapAuthConfig(
                tenants=(BootstrapTenant(slug="acme", name="Acme", users=()),),
                admin=DEFAULT_BOOTSTRAP_AUTH.admin,
            )
            self.reloaded: list[BootstrapAuthConfig] = []

        async def reload(self, config: BootstrapAuthConfig) -> None:
            self.config = config
            self.reloaded.append(config)

    class StubTenantsStore:
        def __init__(self) -> None:
            self.records: dict[str, BootstrapTenantRecord] = {}

        async def get(self, *, filters: Mapping[str, object] | None = None) -> BootstrapTenantRecord | None:
            slug = cast(str | None, (filters or {}).get("slug"))
            return self.records.get(slug) if slug else None

        async def create(
            self,
            data: Mapping[str, object] | BootstrapTenantRecord,
        ) -> BootstrapTenantRecord:
            if isinstance(data, Mapping):
                record = BootstrapTenantRecord(slug=cast(str, data["slug"]), name=cast(str, data["name"]))
            else:
                record = data
            self.records[record.slug] = record
            return record

        async def list(self, *, order_by: Sequence[str] = ()) -> list[BootstrapTenantRecord]:
            return [self.records[key] for key in sorted(self.records.keys())]

    class StubTrialExtensionsStore:
        def __init__(self) -> None:
            self.records: list[BootstrapTrialExtensionRecord] = []

        async def create(self, record: BootstrapTrialExtensionRecord) -> BootstrapTrialExtensionRecord:
            self.records.append(record)
            return record

        async def list(self, *, order_by: Sequence[str] = ()) -> list[BootstrapTrialExtensionRecord]:
            return list(self.records)

    class StubSupportTicketsStore:
        def __init__(self) -> None:
            self.records: dict[str, BootstrapSupportTicketRecord] = {}

        async def create(self, record: BootstrapSupportTicketRecord) -> BootstrapSupportTicketRecord:
            self.records[record.id] = record
            return record

        async def get(self, *, filters: Mapping[str, object] | None = None) -> BootstrapSupportTicketRecord | None:
            if not filters:
                return None
            ticket_id = cast(str | None, filters.get("id"))
            if ticket_id is None:
                return None
            return self.records.get(ticket_id)

        async def update(
            self,
            *,
            filters: Mapping[str, object],
            values: Mapping[str, object],
        ) -> BootstrapSupportTicketRecord:
            ticket_id = cast(str, filters["id"])
            record = self.records[ticket_id]
            updated = structs.replace(record, **values)
            self.records[ticket_id] = updated
            return updated

        async def list(self, *, order_by: Sequence[str] = ()) -> list[BootstrapSupportTicketRecord]:
            return list(self.records.values())

    class StubTenantSupportTicketsStore:
        def __init__(self) -> None:
            self.records: defaultdict[str, dict[str, BootstrapTenantSupportTicketRecord]] = defaultdict(dict)

        async def create(
            self,
            data: BootstrapTenantSupportTicketRecord,
            *,
            tenant: TenantContext,
        ) -> BootstrapTenantSupportTicketRecord:
            self.records[tenant.tenant][data.admin_ticket_id] = data
            return data

        async def get(
            self,
            *,
            tenant: TenantContext,
            filters: Mapping[str, object],
        ) -> BootstrapTenantSupportTicketRecord | None:
            ticket_id = cast(str, filters["admin_ticket_id"])
            return self.records[tenant.tenant].get(ticket_id)

        async def update(
            self,
            *,
            tenant: TenantContext,
            filters: Mapping[str, object],
            values: Mapping[str, object],
        ) -> BootstrapTenantSupportTicketRecord:
            ticket_id = cast(str, filters["admin_ticket_id"])
            record = self.records[tenant.tenant][ticket_id]
            updated = structs.replace(record, **values)
            self.records[tenant.tenant][ticket_id] = updated
            return updated

        async def list(
            self,
            *,
            tenant: TenantContext,
            order_by: Sequence[str] = (),
        ) -> list[BootstrapTenantSupportTicketRecord]:
            return list(self.records[tenant.tenant].values())

    stub_orm: ORM = cast(
        ORM,
        SimpleNamespace(
            admin=SimpleNamespace(
                bootstrap_tenants=StubTenantsStore(),
                bootstrap_trial_extensions=StubTrialExtensionsStore(),
                support_tickets=StubSupportTicketsStore(),
            ),
            tenants=SimpleNamespace(
                support_tickets=StubTenantSupportTicketsStore(),
            ),
        ),
    )

    raw_engine = StubAuthEngine()
    engine = cast(BootstrapAuthEngine, raw_engine)

    trial_store = cast(StubTrialExtensionsStore, stub_orm.admin.bootstrap_trial_extensions)
    admin_ticket_store = cast(StubSupportTicketsStore, stub_orm.admin.support_tickets)
    tenant_ticket_store = cast(StubTenantSupportTicketsStore, stub_orm.tenants.support_tickets)
    ensure_calls: list[str] = []

    async def ensure_contexts(slugs: Iterable[str]) -> None:
        ensure_calls.extend(slugs)

    synced_configs: list[BootstrapAuthConfig] = []

    def sync_allowed_tenants(config: BootstrapAuthConfig) -> None:
        synced_configs.append(config)
        app.tenant_resolver.allowed_tenants.update(tenant.slug for tenant in config.tenants)
        app.tenant_resolver.allowed_tenants.discard(app.config.admin_subdomain)
        app.tenant_resolver.allowed_tenants.discard(app.config.marketing_tenant)

    admin_control = BootstrapAdminControlPlane(
        app,
        slug_normalizer=lambda raw: raw.strip().lower(),
        slug_pattern=bootstrap._TENANT_SLUG_PATTERN,
        ensure_contexts=ensure_contexts,
        chatops=control,
        sync_allowed_tenants=sync_allowed_tenants,
    )

    with pytest.raises(HTTPError) as invalid_slug:
        await admin_control.create_tenant_from_inputs(
            "!!bad!!",
            "Bad",
            orm=stub_orm,
            engine=engine,
            actor="tester",
            source="chatops",
        )
    _assert_error_detail(invalid_slug, "invalid_slug")

    with pytest.raises(HTTPError) as invalid_name:
        await admin_control.create_tenant_from_inputs(
            "gamma",
            "  ",
            orm=stub_orm,
            engine=engine,
            actor="tester",
            source="chatops",
        )
    _assert_error_detail(invalid_name, "invalid_name")

    with pytest.raises(HTTPError) as reserved_slug:
        await admin_control.create_tenant_from_inputs(
            app.config.admin_subdomain,
            "Admin",
            orm=stub_orm,
            engine=engine,
            actor="tester",
            source="chatops",
        )
    _assert_error_detail(reserved_slug, "slug_reserved")

    await stub_orm.admin.bootstrap_tenants.create({"slug": "existing", "name": "Existing"})
    with pytest.raises(HTTPError) as tenant_exists:
        await admin_control.create_tenant_from_inputs(
            "existing",
            "Existing",
            orm=stub_orm,
            engine=engine,
            actor="tester",
            source="chatops",
        )
    _assert_error_detail(tenant_exists, "tenant_exists")

    record = await admin_control.create_tenant_from_inputs(
        "delta",
        "Delta",
        orm=stub_orm,
        engine=engine,
        actor="tester",
        source="api",
    )
    assert record.slug == "delta"
    assert "delta" in ensure_calls
    assert raw_engine.reloaded and raw_engine.config.tenants[-1].slug == "delta"
    assert synced_configs and synced_configs[-1].tenants[-1].slug == "delta"
    assert events[-1][1].extra["slug"] == "delta"

    with pytest.raises(HTTPError) as invalid_trial_slug:
        await admin_control.grant_trial_extension(
            "!!bad!!",
            3,
            note=None,
            actor="tester",
            orm=stub_orm,
        )
    _assert_error_detail(invalid_trial_slug, "invalid_slug")

    with pytest.raises(HTTPError) as invalid_trial_days:
        await admin_control.grant_trial_extension(
            "delta",
            0,
            note=None,
            actor="tester",
            orm=stub_orm,
        )
    _assert_error_detail(invalid_trial_days, "invalid_days")

    with pytest.raises(HTTPError) as missing_trial_tenant:
        await admin_control.grant_trial_extension(
            "unknown",
            3,
            note=None,
            actor="tester",
            orm=stub_orm,
        )
    _assert_error_detail(missing_trial_tenant, "tenant_missing")

    extension = await admin_control.grant_trial_extension(
        "delta",
        5,
        note="  extend  ",
        actor="tester",
        orm=stub_orm,
    )
    assert isinstance(extension, BootstrapTrialExtensionRecord)
    assert extension.note == "extend"
    assert trial_store.records[-1] is extension

    tenant_context = TenantContext(
        tenant="delta",
        site=app.config.site,
        domain=app.config.domain,
        scope=TenantScope.TENANT,
    )

    with pytest.raises(HTTPError) as invalid_ticket:
        await admin_control.create_support_ticket(
            tenant_context,
            BootstrapSupportTicketRequest(subject=" ", message="Issue", kind="general"),
            orm=stub_orm,
            actor="delta-admin",
        )
    _assert_error_detail(invalid_ticket, "invalid_ticket")

    ticket_request = BootstrapSupportTicketRequest(
        subject="Login issue",
        message="Cannot access dashboard",
        kind="issue",
    )
    ticket = await admin_control.create_support_ticket(
        tenant_context,
        ticket_request,
        orm=stub_orm,
        actor="delta-admin",
    )
    assert ticket.tenant_slug == "delta"
    assert ticket.id in admin_ticket_store.records
    assert ticket.id in tenant_ticket_store.records["delta"]

    metrics = await admin_control.tenant_metrics(stub_orm)
    assert metrics["support_tickets"]["open"] == 1

    diagnostics = await admin_control.system_diagnostics(stub_orm)
    assert diagnostics["chatops"]["enabled"] is True
    assert diagnostics["support"]["open"] == 1

    with pytest.raises(HTTPError) as missing_ticket:
        await admin_control.update_support_ticket(
            "missing",
            BootstrapSupportTicketUpdateRequest(status="responded", note=None),
            orm=stub_orm,
            actor="agent",
        )
    _assert_error_detail(missing_ticket, "ticket_missing")

    update_payload = BootstrapSupportTicketUpdateRequest(status="responded", note=" Investigating ")
    updated_ticket = await admin_control.update_support_ticket(
        ticket.id,
        update_payload,
        orm=stub_orm,
        actor="agent",
    )
    assert updated_ticket.status == SupportTicketStatus.RESPONDED
    tenant_ticket = tenant_ticket_store.records["delta"][ticket.id]
    assert tenant_ticket.status == SupportTicketStatus.RESPONDED
    assert tenant_ticket.updates[-1].note == "Investigating"

    metrics_after = await admin_control.tenant_metrics(stub_orm)
    assert metrics_after["support_tickets"]["total"] == 1


class StubTileService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.list_tiles_result: tuple[TileRecord, ...] = ()
        self.tile_records: dict[str, TileRecord] = {}

    async def create_tile(
        self,
        *,
        tenant,
        workspace_id: str,
        principal,
        payload,
    ) -> TileRecord:
        self.calls.append(
            (
                "create",
                {
                    "tenant": tenant.tenant,
                    "workspace": workspace_id,
                    "principal": None if principal is None else principal.id,
                    "title": payload.title,
                },
            )
        )
        created = TileRecord(
            id="tile-created",
            workspace_id=workspace_id,
            title=payload.title,
            layout=payload.layout,
            description=payload.description,
            data_sources=payload.data_sources,
            ai_insights_enabled=payload.ai_insights_enabled,
        )
        self.tile_records[created.id] = created
        return created

    async def list_tiles(
        self,
        *,
        tenant,
        workspace_id: str,
        principal,
    ) -> tuple[TileRecord, ...]:
        self.calls.append(("list", {"workspace": workspace_id}))
        if self.list_tiles_result:
            return self.list_tiles_result
        default = TileRecord(
            id="tile-default",
            workspace_id=workspace_id,
            title="Default",
            layout={"kind": "chart"},
        )
        return (default,)

    async def get_tile(
        self,
        *,
        tenant,
        workspace_id: str,
        tile_id: str,
        principal,
    ) -> TileRecord:
        self.calls.append(("get", {"workspace": workspace_id, "tile": tile_id}))
        record = self.tile_records.get(tile_id)
        if record is not None:
            return record
        fallback = TileRecord(
            id=tile_id,
            workspace_id=workspace_id,
            title="Fetched",
            layout={"kind": "chart"},
        )
        self.tile_records[tile_id] = fallback
        return fallback

    async def update_tile(
        self,
        *,
        tenant,
        workspace_id: str,
        tile_id: str,
        principal,
        payload,
    ) -> TileRecord:
        self.calls.append(
            (
                "update",
                {
                    "workspace": workspace_id,
                    "tile": tile_id,
                    "payload": msgspec.to_builtins(payload),
                },
            )
        )
        record = TileRecord(
            id=tile_id,
            workspace_id=workspace_id,
            title=payload.title or "updated",
            layout=payload.layout or {"kind": "chart"},
            description=payload.description,
        )
        self.tile_records[tile_id] = record
        return record

    async def delete_tile(
        self,
        *,
        tenant,
        workspace_id: str,
        tile_id: str,
        principal,
    ) -> None:
        self.calls.append(("delete", {"workspace": workspace_id, "tile": tile_id}))
        self.tile_records.pop(tile_id, None)

    async def set_permissions(
        self,
        *,
        tenant,
        workspace_id: str,
        tile_id: str,
        principal,
        permissions,
    ) -> TilePermissions:
        self.calls.append(("permissions", {"workspace": workspace_id, "tile": tile_id}))
        return permissions


class StubRbacService:
    def __init__(self) -> None:
        self.permission_sets: list[dict[str, object]] = []
        self.assignments: list[dict[str, object]] = []

    async def create_permission_set(
        self,
        *,
        tenant,
        workspace_id: str,
        principal,
        payload,
    ) -> PermissionSetRecord:
        self.permission_sets.append({"workspace": workspace_id, "payload": msgspec.to_builtins(payload)})
        return PermissionSetRecord(
            id="ps-1",
            workspace_id=workspace_id,
            name=payload.name,
            permissions=payload.permissions,
            role_id="role-ps-1",
            description=payload.description,
        )

    async def assign_role(
        self,
        *,
        tenant,
        workspace_id: str,
        role_id: str,
        principal,
        payload,
    ) -> RoleAssignmentResult:
        self.assignments.append(
            {
                "workspace": workspace_id,
                "role": role_id,
                "users": payload.user_ids,
            }
        )
        return RoleAssignmentResult(
            role_id=role_id,
            workspace_id=workspace_id,
            assigned_user_ids=payload.user_ids,
        )


class StubDelegationService:
    def __init__(self) -> None:
        self.grants: list[dict[str, object]] = []
        self.revocations: list[str] = []

    async def grant(self, *, tenant, principal, payload) -> DelegationRecord:
        self.grants.append(
            {
                "scopes": payload.scopes,
                "from": payload.from_user_id,
                "workspace": payload.workspace_id,
            }
        )
        return DelegationRecord(
            id="del-1",
            from_user_id=payload.from_user_id,
            to_user_id=payload.to_user_id,
            scopes=payload.scopes,
            workspace_id=payload.workspace_id,
            starts_at=payload.starts_at,
            ends_at=payload.ends_at,
            created_by=principal.id if principal else "system",
        )

    async def revoke(self, *, tenant, principal, delegation_id: str) -> None:
        self.revocations.append(delegation_id)


class StubAuditService:
    def __init__(self) -> None:
        self.read_calls: list[dict[str, object]] = []
        self.export_calls: list[dict[str, object]] = []

    async def read(
        self,
        *,
        tenant,
        workspace_id: str,
        principal,
        actor: str | None = None,
        action: str | None = None,
        entity: str | None = None,
        from_time: dt.datetime | None = None,
        to_time: dt.datetime | None = None,
    ) -> AuditLogPage:
        self.read_calls.append(
            {
                "workspace": workspace_id,
                "actor": actor,
                "action": action,
                "from": from_time,
                "to": to_time,
            }
        )
        return AuditLogPage(
            entries=(
                AuditLogEntry(
                    id="aud-1",
                    timestamp=dt.datetime.now(dt.timezone.utc),
                    actor=actor or "demo",
                    action=action or "view",
                    entity_type="tile",
                    entity_id="tile-1",
                ),
            ),
        )

    async def export(
        self,
        *,
        tenant,
        workspace_id: str,
        principal,
        query,
        actor: str | None = None,
        action: str | None = None,
        entity: str | None = None,
        from_time: dt.datetime | None = None,
        to_time: dt.datetime | None = None,
    ) -> AuditLogExport:
        self.export_calls.append(
            {
                "workspace": workspace_id,
                "format": query.format,
                "actor": actor,
            }
        )
        content_type = "text/csv" if query.format == "csv" else "application/json"
        body = b"id,action\naud-1,view" if query.format == "csv" else b"[]"
        return AuditLogExport(
            content_type=content_type,
            body=body,
            filename=f"audit.{query.format}" if query.format == "csv" else None,
        )


class _StubManager:
    def __init__(self, records: Sequence[Any]) -> None:
        self._records = list(records)

    @staticmethod
    def _matches(record: Any, filters: dict[str, object] | None) -> bool:
        if not filters:
            return True
        for key, value in filters.items():
            if getattr(record, key) != value:
                return False
        return True

    async def list(
        self,
        *,
        tenant: TenantContext | None = None,
        filters: dict[str, object] | None = None,
        order_by: Iterable[str] | None = None,
    ) -> list[Any]:
        items = [record for record in self._records if self._matches(record, filters)]
        if order_by:
            field_parts = next(iter(order_by)).split()
            field = field_parts[0]
            reverse = any(part.lower() == "desc" for part in field_parts[1:])
            items.sort(key=lambda item: getattr(item, field), reverse=reverse)
        return list(items)

    async def get(
        self,
        *,
        tenant: TenantContext | None = None,
        filters: dict[str, object] | None = None,
    ) -> Any | None:
        for record in reversed(self._records):
            if self._matches(record, filters):
                return record
        return None


class StubWorkspaceOrm:
    def __init__(
        self,
        *,
        admin_records: Mapping[str, Sequence[Any]],
        tenant_records: Mapping[str, Sequence[Any]],
    ) -> None:
        self.admin = SimpleNamespace(
            bootstrap_tenants=_StubManager(admin_records.get("bootstrap_tenants", ())),
            bootstrap_trial_extensions=_StubManager(admin_records.get("bootstrap_trial_extensions", ())),
            support_tickets=_StubManager(admin_records.get("support_tickets", ())),
            billing=_StubManager(admin_records.get("billing", ())),
        )
        self.tenants = SimpleNamespace(
            support_tickets=_StubManager(tenant_records.get("support_tickets", ())),
        )


def _build_bootstrap_app(
    monkeypatch: pytest.MonkeyPatch,
    *,
    allowed_tenants: tuple[str, ...] = ("acme",),
) -> MereApp:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://bootstrap"))
    database = Database(db_config, pool=pool)
    config = AppConfig(site="demo", domain="local.test", allowed_tenants=allowed_tenants, database=db_config)
    app = MereApp(config=config, database=database, bootstrap_enabled=False)

    async def _noop_apply(
        self: bootstrap.BootstrapSeeder,
        config: bootstrap.BootstrapAuthConfig,
        *,
        tenants: Mapping[str, TenantContext],
    ) -> bool:
        return False

    async def _noop_run_all(
        self: bootstrap.MigrationRunner,
        *,
        tenants: Sequence[TenantContext],
    ) -> None:
        return None

    async def _noop_ensure(
        database: Database,
        tenants: Sequence[TenantContext],
    ) -> None:
        return None

    monkeypatch.setattr(bootstrap.BootstrapSeeder, "apply", _noop_apply)
    monkeypatch.setattr(bootstrap.MigrationRunner, "run_all", _noop_run_all)
    monkeypatch.setattr(bootstrap, "ensure_tenant_schemas", _noop_ensure)
    app.dependencies.provide(TileService, lambda: object())
    attach_bootstrap(app)
    return app


@pytest.mark.asyncio
async def test_bootstrap_tile_routes_delegate_to_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)
    stub = StubTileService()
    app.dependencies.provide(TileService, lambda: stub)
    stub.list_tiles_result = (
        TileRecord(
            id="tile-list",
            workspace_id="acme",
            title="Pipeline",
            layout={"kind": "chart"},
        ),
    )
    stub.tile_records["tile-1"] = TileRecord(
        id="tile-1",
        workspace_id="acme",
        title="Existing",
        layout={"kind": "table"},
    )

    async with TestClient(app) as client:
        listing = await client.get(
            "/__mere/workspaces/acme/tiles",
            tenant="acme",
        )
        assert listing.status == Status.OK
        listing_payload = json.loads(listing.body.decode())
        assert listing_payload[0]["id"] == "tile-list"

        detail = await client.get(
            "/__mere/workspaces/acme/tiles/tile-1",
            tenant="acme",
        )
        assert detail.status == Status.OK
        detail_payload = json.loads(detail.body.decode())
        assert detail_payload["id"] == "tile-1"

        create = await client.post(
            "/__mere/workspaces/acme/tiles",
            tenant="acme",
            json={"title": "Sales", "layout": {"type": "chart"}},
        )
        assert create.status == Status.CREATED
        update = await client.request(
            "PATCH",
            "/__mere/workspaces/acme/tiles/tile-1",
            tenant="acme",
            json={"description": "Updated"},
        )
        assert update.status == 200
        delete = await client.request(
            "DELETE",
            "/__mere/workspaces/acme/tiles/tile-1",
            tenant="acme",
        )
        assert delete.status == Status.NO_CONTENT
        permissions = await client.request(
            "PUT",
            "/__mere/workspaces/acme/tiles/tile-1/permissions",
            tenant="acme",
            json={"roles": ["viewer"], "users": ["user-1"]},
        )
        assert permissions.status == 200
        assert [call[0] for call in stub.calls] == [
            "list",
            "get",
            "create",
            "update",
            "delete",
            "permissions",
        ]


@pytest.mark.asyncio
async def test_bootstrap_workspace_views_return_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)
    tile_service = StubTileService()
    tile_service.list_tiles_result = (
        TileRecord(
            id="tile-analytics",
            workspace_id="acme",
            title="Analytics",
            layout={"kind": "chart"},
            ai_insights_enabled=True,
        ),
    )
    tile_service.tile_records["tile-analytics"] = tile_service.list_tiles_result[0]
    app.dependencies.provide(TileService, lambda: tile_service)

    base = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    admin_records = {
        "bootstrap_tenants": (
            bootstrap.BootstrapTenantRecord(
                id="tenant-acme",
                slug="acme",
                name="Acme Rockets",
                created_at=base,
                updated_at=base,
            ),
        ),
        "bootstrap_trial_extensions": (
            bootstrap.BootstrapTrialExtensionRecord(
                id="trial-acme",
                tenant_slug="acme",
                extended_days=14,
                requested_by="ops",
                created_at=base,
                updated_at=base + dt.timedelta(hours=1),
            ),
        ),
        "support_tickets": (
            SupportTicket(
                id="ticket-1",
                tenant_slug="acme",
                kind=SupportTicketKind.ISSUE,
                subject="API latency",
                message="Investigate elevated latency",
                status=SupportTicketStatus.RESPONDED,
                updates=(
                    SupportTicketUpdate(
                        timestamp=base + dt.timedelta(hours=2),
                        actor="eng",
                        note="Working on mitigation",
                    ),
                ),
                created_at=base,
                updated_at=base + dt.timedelta(hours=3),
                updated_by="eng",
            ),
            SupportTicket(
                id="ticket-2",
                tenant_slug="acme",
                kind=SupportTicketKind.FEEDBACK,
                subject="Product feedback",
                message="Customers love the dashboards",
                status=SupportTicketStatus.RESOLVED,
                updates=(),
                created_at=base + dt.timedelta(hours=1),
                updated_at=base + dt.timedelta(hours=5),
                updated_by="success",
            ),
            SupportTicket(
                id="ticket-3",
                tenant_slug="acme",
                kind=SupportTicketKind.GENERAL,
                subject="General inquiry",
                message="Need help with billing",
                status=SupportTicketStatus.OPEN,
                updates=(),
                created_at=base + dt.timedelta(hours=2),
                updated_at=base + dt.timedelta(hours=2),
                updated_by="ops",
            ),
        ),
        "billing": (
            BillingRecord(
                id="billing-1",
                customer_id="acme",
                plan_code="pro",
                status=BillingStatus.PAST_DUE,
                amount_due_cents=12000,
                currency="USD",
                cycle_start=base,
                cycle_end=base + dt.timedelta(days=30),
                created_at=base,
                updated_at=base + dt.timedelta(hours=4),
            ),
            BillingRecord(
                id="billing-2",
                customer_id="acme",
                plan_code="pro",
                status=BillingStatus.CANCELED,
                amount_due_cents=0,
                currency="USD",
                cycle_start=base,
                cycle_end=base + dt.timedelta(days=30),
                created_at=base,
                updated_at=base + dt.timedelta(hours=6),
            ),
            BillingRecord(
                id="billing-3",
                customer_id="acme",
                plan_code="enterprise",
                status=BillingStatus.ACTIVE,
                amount_due_cents=50000,
                currency="USD",
                cycle_start=base,
                cycle_end=base + dt.timedelta(days=30),
                created_at=base,
                updated_at=base + dt.timedelta(hours=7),
            ),
        ),
    }
    tenant_records = {
        "support_tickets": (
            bootstrap.BootstrapTenantSupportTicketRecord(
                id="tenant-ticket-1",
                admin_ticket_id="ticket-1",
                kind=SupportTicketKind.ISSUE,
                subject="API latency",
                message="Investigate elevated latency",
                status=SupportTicketStatus.OPEN,
                updates=(),
                created_at=base,
                updated_at=base + dt.timedelta(hours=4),
                created_by="ops",
                updated_by="ops",
            ),
            bootstrap.BootstrapTenantSupportTicketRecord(
                id="tenant-ticket-2",
                admin_ticket_id="ticket-3",
                kind=SupportTicketKind.GENERAL,
                subject="General inquiry",
                message="Need help with billing",
                status=SupportTicketStatus.OPEN,
                updates=(),
                created_at=base + dt.timedelta(hours=2),
                updated_at=base + dt.timedelta(hours=2),
                created_by="ops",
                updated_by="ops",
            ),
        ),
    }
    orm = StubWorkspaceOrm(admin_records=admin_records, tenant_records=tenant_records)
    app.dependencies.provide(ORM, lambda: orm)

    async with TestClient(app) as client:
        settings = await client.get(
            "/__mere/workspaces/acme/settings",
            tenant="acme",
        )
        assert settings.status == Status.OK
        settings_payload = json.loads(settings.body.decode())
        assert settings_payload["workspaceId"] == "acme"
        assert settings_payload["tileCount"] == 1
        assert settings_payload["alerts"]

        notifications = await client.get(
            "/__mere/workspaces/acme/notifications",
            tenant="acme",
        )
        assert notifications.status == Status.OK
        feed = json.loads(notifications.body.decode())
        assert any(item["kind"] == "billing" for item in feed)

        kanban = await client.get(
            "/__mere/workspaces/acme/kanban",
            tenant="acme",
        )
        assert kanban.status == Status.OK
        board = json.loads(kanban.body.decode())
        assert board["workspaceId"] == "acme"
        assert {column["key"] for column in board["columns"]} == {
            "backlog",
            "in_progress",
            "done",
        }
        assert any(column["cards"] for column in board["columns"])


@pytest.mark.asyncio
async def test_bootstrap_workspace_views_return_sample_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)

    class EmptyTileService(StubTileService):
        async def list_tiles(
            self,
            *,
            tenant,
            workspace_id: str,
            principal,
        ) -> tuple[TileRecord, ...]:
            self.calls.append(("list", {"workspace": workspace_id}))
            return ()

    tile_service = EmptyTileService()
    app.dependencies.provide(TileService, lambda: tile_service)
    orm = StubWorkspaceOrm(admin_records={}, tenant_records={})
    app.dependencies.provide(ORM, lambda: orm)

    async with TestClient(app) as client:
        settings = await client.get(
            "/__mere/workspaces/acme/settings",
            tenant="acme",
        )
        assert settings.status == Status.OK
        settings_payload = json.loads(settings.body.decode())
        assert settings_payload["tileCount"] == 0
        assert "acme-billing-setup" in settings_payload["alerts"]

        notifications = await client.get(
            "/__mere/workspaces/acme/notifications",
            tenant="acme",
        )
        assert notifications.status == Status.OK
        feed = json.loads(notifications.body.decode())
        assert len(feed) == 3

        kanban = await client.get(
            "/__mere/workspaces/acme/kanban",
            tenant="acme",
        )
        assert kanban.status == Status.OK
        board = json.loads(kanban.body.decode())
        assert any(column["cards"] for column in board["columns"])


@pytest.mark.asyncio
async def test_bootstrap_workspace_views_return_sample_without_orm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)
    app.dependencies.provide(TileService, StubTileService)
    app.dependencies.provide(ORM, lambda: None)

    async with TestClient(app) as client:
        notifications = await client.get(
            "/__mere/workspaces/acme/notifications",
            tenant="acme",
        )
        assert notifications.status == Status.OK
        feed = json.loads(notifications.body.decode())
        assert feed[0]["id"].startswith("acme-")

        kanban = await client.get(
            "/__mere/workspaces/acme/kanban",
            tenant="acme",
        )
        assert kanban.status == Status.OK
        board = json.loads(kanban.body.decode())
        assert board["workspaceId"] == "acme"
        assert any(column["cards"] for column in board["columns"])


@pytest.mark.asyncio
async def test_bootstrap_workspace_routes_reject_cross_tenant_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch, allowed_tenants=("acme", "beta"))
    app.dependencies.provide(TileService, StubTileService)
    orm = StubWorkspaceOrm(admin_records={}, tenant_records={})
    app.dependencies.provide(ORM, lambda: orm)

    async with TestClient(app) as client:
        forbidden = await client.get(
            "/__mere/workspaces/acme/notifications",
            tenant="beta",
        )
        assert forbidden.status == Status.FORBIDDEN


@pytest.mark.asyncio
async def test_bootstrap_workspace_context_created_on_demand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)
    orm = StubWorkspaceOrm(admin_records={}, tenant_records={})
    app.dependencies.provide(ORM, lambda: orm)

    async with TestClient(app) as client:
        board = await client.get(
            "/__mere/workspaces/omega/kanban",
            tenant=app.config.admin_subdomain,
        )
        assert board.status == Status.OK
        payload = json.loads(board.body.decode())
        assert payload["workspaceId"] == "omega"


class _TruthyEmptySequence:
    def __iter__(self) -> Iterable[BootstrapKanbanCard]:
        return iter(())

    def __bool__(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_bootstrap_workspace_kanban_returns_sample_for_empty_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)
    orm = StubWorkspaceOrm(admin_records={}, tenant_records={})

    async def _truthy_empty(
        self: _StubManager,
        *,
        tenant: TenantContext | None = None,
        filters: dict[str, object] | None = None,
        order_by: Iterable[str] | None = None,
    ) -> _TruthyEmptySequence:
        return _TruthyEmptySequence()

    orm.tenants.support_tickets.list = types.MethodType(_truthy_empty, orm.tenants.support_tickets)
    app.dependencies.provide(ORM, lambda: orm)

    async with TestClient(app) as client:
        board = await client.get(
            "/__mere/workspaces/acme/kanban",
            tenant="acme",
        )
        assert board.status == Status.OK
        payload = json.loads(board.body.decode())
        assert payload["workspaceId"] == "acme"
        assert any(column["cards"] for column in payload["columns"])


@pytest.mark.asyncio
async def test_bootstrap_rbac_routes_require_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)
    stub = StubRbacService()
    app.dependencies.provide(RbacService, lambda: stub)

    async with TestClient(app) as client:
        forbidden = await client.post(
            "/__mere/workspaces/ws-1/rbac/permission-sets",
            tenant="acme",
            json={"name": "ops", "permissions": ["tiles:read"]},
        )
        assert forbidden.status == Status.FORBIDDEN

        created = await client.post(
            "/__mere/workspaces/ws-1/rbac/permission-sets",
            tenant=app.config.admin_subdomain,
            json={"name": "ops", "permissions": ["tiles:read"]},
        )
        assert created.status == Status.CREATED
        assigned = await client.post(
            "/__mere/workspaces/ws-1/rbac/roles/role-ps-1/assign",
            tenant=app.config.admin_subdomain,
            json={"userIds": ["user-1"]},
        )
        assert assigned.status == 200
        assert stub.permission_sets
        assert stub.assignments


@pytest.mark.asyncio
async def test_bootstrap_delegation_routes_delegate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)
    stub = StubDelegationService()
    app.dependencies.provide(DelegationService, lambda: stub)

    start = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    end = dt.datetime(2024, 1, 2, tzinfo=dt.timezone.utc)

    async with TestClient(app) as client:
        admin_forbidden = await client.post(
            "/__mere/delegations",
            tenant=app.config.admin_subdomain,
            json={
                "workspaceId": "ws-1",
                "fromUserId": "user-1",
                "toUserId": "user-2",
                "scopes": ["tiles:read"],
                "startsAt": start.isoformat(),
                "endsAt": end.isoformat(),
            },
        )
        assert admin_forbidden.status == Status.FORBIDDEN

        grant = await client.post(
            "/__mere/delegations",
            tenant="acme",
            json={
                "workspaceId": "ws-1",
                "fromUserId": "user-1",
                "toUserId": "user-2",
                "scopes": ["tiles:read"],
                "startsAt": start.isoformat(),
                "endsAt": end.isoformat(),
            },
        )
        assert grant.status == Status.CREATED
        admin_delete = await client.request(
            "DELETE",
            "/__mere/delegations/del-1",
            tenant=app.config.admin_subdomain,
        )
        assert admin_delete.status == Status.FORBIDDEN
        revoke = await client.request(
            "DELETE",
            "/__mere/delegations/del-1",
            tenant="acme",
        )
        assert revoke.status == Status.NO_CONTENT
        assert stub.grants
        assert stub.revocations == ["del-1"]


@pytest.mark.asyncio
async def test_bootstrap_cedar_dependency_handles_missing_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def stub_build(orm: bootstrap.ORM, *, tenant: TenantContext, at: dt.datetime | None = None) -> CedarEngine:
        if tenant.scope is TenantScope.TENANT and tenant.tenant == "acme":
            return CedarEngine(())
        raise HTTPError(Status.NOT_FOUND, {"detail": "missing"})

    monkeypatch.setattr(bootstrap, "build_cedar_engine", stub_build)
    app = _build_bootstrap_app(monkeypatch)

    tenant_request = Request(
        method="GET",
        path="/__mere/workspaces/acme/tiles",
        tenant=TenantContext(
            tenant="acme",
            site=app.config.site,
            domain=app.config.domain,
            scope=TenantScope.TENANT,
        ),
        path_params={"wsId": "acme"},
    )
    tenant_scope = app.dependencies.scope(tenant_request)
    tenant_engine = await tenant_scope.get(CedarEngine)
    assert isinstance(tenant_engine, CedarEngine)

    admin_request = Request(
        method="GET",
        path="/__mere/workspaces/ws-1/rbac/permission-sets",
        tenant=TenantContext(
            tenant=app.config.admin_subdomain,
            site=app.config.site,
            domain=app.config.domain,
            scope=TenantScope.ADMIN,
        ),
        path_params={"wsId": "ws-1"},
    )
    admin_scope = app.dependencies.scope(admin_request)
    empty_engine = await admin_scope.get(CedarEngine)
    assert isinstance(empty_engine, CedarEngine)
    assert not empty_engine.policies()

    admin_missing = Request(
        method="GET",
        path="/__mere/diagnostics",
        tenant=TenantContext(
            tenant=app.config.admin_subdomain,
            site=app.config.site,
            domain=app.config.domain,
            scope=TenantScope.ADMIN,
        ),
    )
    admin_missing_engine = await app.dependencies.scope(admin_missing).get(CedarEngine)
    assert isinstance(admin_missing_engine, CedarEngine)
    assert not admin_missing_engine.policies()

    public_request = Request(
        method="GET",
        path="/__mere/ping",
        tenant=TenantContext(
            tenant="public",
            site=app.config.site,
            domain=app.config.domain,
            scope=TenantScope.PUBLIC,
        ),
    )
    public_engine = await app.dependencies.scope(public_request).get(CedarEngine)
    assert isinstance(public_engine, CedarEngine)
    assert not public_engine.policies()


@pytest.mark.asyncio
async def test_bootstrap_audit_routes_delegate_to_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_bootstrap_app(monkeypatch)
    stub = StubAuditService()
    app.dependencies.provide(AuditService, lambda: stub)

    async with TestClient(app) as client:
        logs = await client.get(
            "/__mere/workspaces/ws-1/audit-logs",
            tenant=app.config.admin_subdomain,
            query={"actor": "admin", "from": "2024-01-01T00:00:00Z"},
        )
        assert logs.status == 200
        export = await client.get(
            "/__mere/workspaces/ws-1/audit-logs/export",
            tenant=app.config.admin_subdomain,
            query={"format": "csv"},
        )
        assert export.status == 200
        header_map = dict(export.headers)
        assert header_map["content-type"] == "text/csv"
        assert stub.read_calls
        assert stub.export_calls[0]["format"] == "csv"
        export_json = await client.get(
            "/__mere/workspaces/ws-1/audit-logs/export",
            tenant=app.config.admin_subdomain,
        )
        assert export_json.status == 200
        json_headers = dict(export_json.headers)
        assert "content-disposition" not in json_headers
