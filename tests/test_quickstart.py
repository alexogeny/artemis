from __future__ import annotations

import json
import types
from pathlib import Path
from typing import Mapping, Sequence, cast

import pytest

import artemis.quickstart as quickstart
from artemis import AppConfig, ArtemisApp, PasskeyManager, SessionLevel, TestClient
from artemis.database import Database, DatabaseConfig, PoolConfig
from artemis.exceptions import HTTPError
from artemis.http import Status
from artemis.migrations import MigrationRunner
from artemis.orm import ORM
from artemis.quickstart import (
    DEFAULT_QUICKSTART_AUTH,
    LoginStep,
    MfaAttempt,
    PasskeyAttempt,
    PasswordAttempt,
    QuickstartAdminRealm,
    QuickstartAdminUserRecord,
    QuickstartAuthConfig,
    QuickstartAuthEngine,
    QuickstartPasskey,
    QuickstartPasskeyRecord,
    QuickstartRepository,
    QuickstartSeeder,
    QuickstartSeedStateRecord,
    QuickstartSsoProvider,
    QuickstartTenant,
    QuickstartTenantRecord,
    QuickstartTenantUserRecord,
    QuickstartUser,
    attach_quickstart,
    ensure_tenant_schemas,
    load_quickstart_auth_from_env,
    quickstart_migrations,
)
from artemis.tenancy import TenantContext, TenantScope
from tests.support import FakeConnection, FakePool


def _assert_error_detail(exc: pytest.ExceptionInfo[BaseException], code: str) -> None:
    err = exc.value
    assert isinstance(err, HTTPError)
    assert err.detail["detail"] == code


@pytest.mark.asyncio
async def test_attach_quickstart_routes_dev_environment() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))
    attach_quickstart(app)

    async with TestClient(app) as client:
        for tenant in ("acme", "beta", app.config.admin_subdomain):
            ping = await client.get("/__artemis/ping", tenant=tenant)
            assert ping.status == 200
            assert ping.body.decode() == "pong"

            openapi = await client.get("/__artemis/openapi.json", tenant=tenant)
            assert openapi.status == 200
            spec = json.loads(openapi.body.decode())
            assert "/__artemis/ping" in spec["paths"]

            client_ts = await client.get("/__artemis/client.ts", tenant=tenant)
            assert client_ts.status == 200
            assert ("content-type", "application/typescript") in client_ts.headers
            assert "export class ArtemisClient" in client_ts.body.decode()


def test_attach_quickstart_rejects_production() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta")))
    with pytest.raises(RuntimeError):
        attach_quickstart(app, environment="production")


def test_attach_quickstart_updates_allowed_tenants_from_config() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=()))
    config = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="gamma",
                name="Gamma Corp",
                users=(
                    QuickstartUser(
                        id="usr_gamma_owner",
                        email="owner@gamma.test",
                        password="gamma-pass",
                    ),
                ),
            ),
        ),
        admin=DEFAULT_QUICKSTART_AUTH.admin,
    )

    attach_quickstart(app, auth_config=config)

    assert "gamma" in app.tenant_resolver.allowed_tenants


@pytest.mark.asyncio
async def test_attach_quickstart_with_root_base_path() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))
    attach_quickstart(app, base_path="")

    async with TestClient(app) as client:
        response = await client.get("/ping", tenant="acme")
        assert response.status == 200
        assert response.body.decode() == "pong"


@pytest.mark.asyncio
async def test_quickstart_sso_login_hint() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))
    attach_quickstart(app)

    async with TestClient(app) as client:
        response = await client.post(
            "/__artemis/auth/login/start",
            tenant="acme",
            json={"email": "founder@acme.test"},
        )
        assert response.status == 200
        payload = json.loads(response.body.decode())
        assert payload["next"] == "sso"
        assert payload["provider"]["redirect_url"].startswith("https://id.acme.test")
        assert payload["fallback"] is None


@pytest.mark.asyncio
async def test_quickstart_passkey_flow_with_mfa() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))
    attach_quickstart(app)

    async with TestClient(app) as client:
        start = await client.post(
            "/__artemis/auth/login/start",
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

        user = DEFAULT_QUICKSTART_AUTH.tenants[1].users[0]
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
            "/__artemis/auth/login/passkey",
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
            "/__artemis/auth/login/mfa",
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
async def test_quickstart_login_flow_times_out() -> None:
    config = QuickstartAuthConfig(
        tenants=DEFAULT_QUICKSTART_AUTH.tenants,
        admin=DEFAULT_QUICKSTART_AUTH.admin,
        flow_ttl_seconds=0,
    )
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("beta",)))
    attach_quickstart(app, auth_config=config)

    async with TestClient(app) as client:
        start = await client.post(
            "/__artemis/auth/login/start",
            tenant="beta",
            json={"email": "ops@beta.test"},
        )
        assert start.status == 200
        flow_token = json.loads(start.body.decode())["flow_token"]

        expired = await client.post(
            "/__artemis/auth/login/password",
            tenant="beta",
            json={"flow_token": flow_token, "password": "beta-password"},
        )
        assert expired.status == Status.GONE
        expired_payload = json.loads(expired.body.decode())
        assert expired_payload["error"]["detail"]["detail"] == "flow_expired"

        restart = await client.post(
            "/__artemis/auth/login/start",
            tenant="beta",
            json={"email": "ops@beta.test"},
        )
        assert restart.status == 200


@pytest.mark.asyncio
async def test_quickstart_login_flow_locks_after_failures() -> None:
    config = QuickstartAuthConfig(
        tenants=DEFAULT_QUICKSTART_AUTH.tenants,
        admin=DEFAULT_QUICKSTART_AUTH.admin,
        max_attempts=2,
    )
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("beta",)))
    attach_quickstart(app, auth_config=config)

    async with TestClient(app) as client:
        start = await client.post(
            "/__artemis/auth/login/start",
            tenant="beta",
            json={"email": "ops@beta.test"},
        )
        assert start.status == 200
        flow_token = json.loads(start.body.decode())["flow_token"]

        first_attempt = await client.post(
            "/__artemis/auth/login/password",
            tenant="beta",
            json={"flow_token": flow_token, "password": "wrong"},
        )
        assert first_attempt.status == Status.UNAUTHORIZED
        first_payload = json.loads(first_attempt.body.decode())
        assert first_payload["error"]["detail"]["detail"] == "invalid_password"

        second_attempt = await client.post(
            "/__artemis/auth/login/password",
            tenant="beta",
            json={"flow_token": flow_token, "password": "wrong"},
        )
        assert second_attempt.status == Status.TOO_MANY_REQUESTS
        second_payload = json.loads(second_attempt.body.decode())
        assert second_payload["error"]["detail"]["detail"] == "flow_locked"


@pytest.mark.asyncio
async def test_quickstart_engine_prunes_expired_flows() -> None:
    engine = QuickstartAuthEngine(DEFAULT_QUICKSTART_AUTH)
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
async def test_quickstart_password_flow_for_admin() -> None:
    app = ArtemisApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))
    attach_quickstart(app)

    admin = DEFAULT_QUICKSTART_AUTH.admin.users[0]

    async with TestClient(app) as client:
        start = await client.post(
            "/__artemis/auth/login/start",
            tenant=app.config.admin_subdomain,
            json={"email": admin.email},
        )
        assert start.status == 200
        start_payload = json.loads(start.body.decode())
        assert start_payload["next"] == "password"
        flow_token = start_payload["flow_token"]

        password_response = await client.post(
            "/__artemis/auth/login/password",
            tenant=app.config.admin_subdomain,
            json={"flow_token": flow_token, "password": admin.password},
        )
        assert password_response.status == 200
        password_payload = json.loads(password_response.body.decode())
        assert password_payload["next"] == "mfa"

        mfa_response = await client.post(
            "/__artemis/auth/login/mfa",
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
async def test_quickstart_migrations_create_tables() -> None:
    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://quickstart"))
    database = Database(db_config, pool=pool)
    tenant_ctx = TenantContext(tenant="acme", site="demo", domain="local.test", scope=TenantScope.TENANT)

    migrations = quickstart_migrations()
    runner = MigrationRunner(database, migrations=migrations, tenant_provider=lambda: (tenant_ctx,))

    await ensure_tenant_schemas(database, [tenant_ctx])
    await runner.run_all(tenants=[tenant_ctx])

    statements = [sql for kind, sql, *_ in connection.calls if kind == "execute"]
    assert any("CREATE TABLE" in sql and "quickstart_tenants" in sql for sql in statements)
    assert any("CREATE TABLE" in sql and "quickstart_users" in sql for sql in statements)


@pytest.mark.asyncio
async def test_quickstart_seeder_persists_config() -> None:
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
            self.created: list[QuickstartSeedStateRecord] = []
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
            data: QuickstartSeedStateRecord,
            *,
            tenant: TenantContext | None = None,
        ) -> QuickstartSeedStateRecord:
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
            quickstart_admin_users=admin_users,
            quickstart_tenants=tenant_records,
            quickstart_seed_state=seed_state,
        ),
        tenants=types.SimpleNamespace(quickstart_users=tenant_users),
    )

    config = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="acme",
                name="Acme Rockets",
                users=(
                    QuickstartUser(
                        id="usr_acme_owner",
                        email="founder@acme.test",
                        password="demo-pass",
                        passkeys=(
                            QuickstartPasskey(
                                credential_id="acme-passkey",
                                secret="passkey-secret",
                                label="YubiKey",
                            ),
                        ),
                        mfa_code="654321",
                        sso=QuickstartSsoProvider(
                            slug="okta",
                            kind="saml",
                            display_name="Okta",
                            redirect_url="https://id.acme.test/sso/start",
                        ),
                    ),
                ),
            ),
        ),
        admin=QuickstartAdminRealm(
            users=(
                QuickstartUser(
                    id="adm_root",
                    email="root@admin.test",
                    password="admin-pass",
                    passkeys=(QuickstartPasskey(credential_id="adm-passkey", secret="adm-secret"),),
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

    seeder = QuickstartSeeder(cast(ORM, orm_stub))
    seeded = await seeder.apply(config, tenants=tenants_map)
    assert seeded is True

    assert len(admin_users.deleted) == 1
    assert len(admin_users.created) == 1
    admin_record = admin_users.created[0][1]
    assert isinstance(admin_record, QuickstartAdminUserRecord)
    assert admin_record.passkeys == (
        QuickstartPasskeyRecord(credential_id="adm-passkey", secret="adm-secret", label=None),
    )

    assert len(tenant_records.deleted) == 1
    assert len(tenant_records.created) == 1
    tenant_record = tenant_records.created[0][1]
    assert isinstance(tenant_record, QuickstartTenantRecord)
    assert tenant_record.slug == "acme"

    assert len(tenant_users.deleted) == 1
    deleted_ctx = tenant_users.deleted[0][0]
    assert isinstance(deleted_ctx, TenantContext)
    assert deleted_ctx.tenant == "acme"

    created_user = tenant_users.created[0][1]
    assert isinstance(created_user, QuickstartTenantUserRecord)
    assert created_user.email == "founder@acme.test"
    assert created_user.passkeys == (
        QuickstartPasskeyRecord(
            credential_id="acme-passkey",
            secret="passkey-secret",
            label="YubiKey",
        ),
    )
    assert created_user.sso_provider is not None

    assert len(seed_state.created) == 1
    created_state = seed_state.created[0]
    assert isinstance(created_state, QuickstartSeedStateRecord)
    assert created_state.key == "quickstart_auth"
    assert seed_state.updated == []


@pytest.mark.asyncio
async def test_quickstart_seeder_skips_when_fingerprint_matches() -> None:
    state_manager = types.SimpleNamespace(
        created=[],
        updated=[],
        state=None,
    )

    class SeedStateManager:
        async def get(self, **_: object) -> object | None:
            return state_manager.state

        async def create(self, data: QuickstartSeedStateRecord, **_: object) -> QuickstartSeedStateRecord:
            state_manager.created.append(data)
            state_manager.state = types.SimpleNamespace(id=data.id, fingerprint=data.fingerprint)
            return data

        async def update(self, values: Mapping[str, object], **_: object) -> list[object]:
            state_manager.updated.append(values)
            if state_manager.state is not None:
                fingerprint = cast(str, values.get("fingerprint", state_manager.state.fingerprint))
                state_manager.state = types.SimpleNamespace(
                    id=state_manager.state.id, fingerprint=fingerprint
                )
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
            quickstart_admin_users=admin_manager,
            quickstart_tenants=tenant_manager,
            quickstart_seed_state=seed_manager,
        ),
        tenants=types.SimpleNamespace(quickstart_users=tenant_users),
    )

    tenant = QuickstartTenant(
        slug="acme",
        name="Acme",
        users=(
            QuickstartUser(
                id="usr_acme",
                email="founder@acme.test",
                password="demo-pass",
            ),
        ),
    )
    config = QuickstartAuthConfig(tenants=(tenant,), admin=DEFAULT_QUICKSTART_AUTH.admin)
    context = TenantContext(tenant="acme", site="demo", domain="local.test", scope=TenantScope.TENANT)
    seeder = QuickstartSeeder(cast(ORM, orm_stub))

    first = await seeder.apply(config, tenants={"acme": context})
    assert first is True
    assert len(admin_manager.deleted) == 1
    assert len(state_manager.created) == 1

    second = await seeder.apply(config, tenants={"acme": context})
    assert second is False
    assert len(admin_manager.deleted) == 1
    assert state_manager.state is not None
    assert state_manager.updated == []

    updated_config = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="acme",
                name="Acme",
                users=(
                    QuickstartUser(
                        id="usr_acme",
                        email="founder@acme.test",
                        password="new-pass",
                    ),
                ),
            ),
        ),
        admin=DEFAULT_QUICKSTART_AUTH.admin,
    )
    third = await seeder.apply(updated_config, tenants={"acme": context})
    assert third is True
    assert len(admin_manager.deleted) == 2
    assert state_manager.updated


@pytest.mark.asyncio
async def test_quickstart_repository_roundtrip() -> None:
    tenant_record = QuickstartTenantRecord(id="tnt_acme", slug="acme", name="Acme")
    tenant_user = QuickstartTenantUserRecord(
        id="usr_acme",
        email="founder@acme.test",
        password="demo-pass",
        passkeys=(
            QuickstartPasskeyRecord(
                credential_id="acme-passkey",
                secret="passkey-secret",
                label="Primary",
            ),
        ),
        mfa_code="654321",
        sso_provider=QuickstartSsoProvider(
            slug="okta",
            kind="saml",
            display_name="Okta",
            redirect_url="https://id.acme.test/sso/start",
        ),
    )
    admin_user = QuickstartAdminUserRecord(
        id="adm_root",
        email="root@admin.test",
        password="admin-pass",
        passkeys=(QuickstartPasskeyRecord(credential_id="adm-passkey", secret="adm-secret", label=None),),
        mfa_code="111111",
    )

    class ListManager:
        def __init__(self, items: list[object]) -> None:
            self._items = items

        async def list(self, **_: object) -> list[object]:
            return list(self._items)

    class TenantUserManager:
        def __init__(self, mapping: dict[str, list[QuickstartTenantUserRecord]]) -> None:
            self._mapping = mapping

        async def list(self, *, tenant: TenantContext, **_: object) -> list[QuickstartTenantUserRecord]:
            return list(self._mapping.get(tenant.tenant, []))

    orm_stub = types.SimpleNamespace(
        admin=types.SimpleNamespace(
            quickstart_tenants=ListManager([tenant_record]),
            quickstart_admin_users=ListManager([admin_user]),
        ),
        tenants=types.SimpleNamespace(
            quickstart_users=TenantUserManager({"acme": [tenant_user]}),
        ),
    )

    repository = QuickstartRepository(cast(ORM, orm_stub), site="demo", domain="local.test")
    config = await repository.load()
    assert config is not None
    assert config.tenants[0].slug == "acme"
    assert config.tenants[0].users[0].passkeys[0].secret == "passkey-secret"
    assert config.admin.users[0].email == "root@admin.test"


@pytest.mark.asyncio
async def test_attach_quickstart_bootstraps_database(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class StubSeeder:
        def __init__(self, orm: ORM) -> None:
            calls["seeder_init"] = orm

        async def apply(self, config: QuickstartAuthConfig, *, tenants: Mapping[str, TenantContext]) -> bool:
            calls["seed_config"] = config
            calls["seed_tenants"] = sorted(tenants)
            return True

    class StubRepository:
        def __init__(self, orm: ORM, *, site: str, domain: str) -> None:
            calls["repository_init"] = (orm, site, domain)

        async def load(self) -> QuickstartAuthConfig | None:
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

    original_reload = quickstart.QuickstartAuthEngine.reload

    async def recording_reload(self: QuickstartAuthEngine, config: QuickstartAuthConfig) -> None:
        calls["reload_config"] = config
        await original_reload(self, config)

    monkeypatch.setattr(quickstart, "QuickstartSeeder", StubSeeder)
    monkeypatch.setattr(quickstart, "QuickstartRepository", StubRepository)
    monkeypatch.setattr(quickstart, "ensure_tenant_schemas", fake_ensure)
    monkeypatch.setattr(MigrationRunner, "run_all", fake_run_all)
    monkeypatch.setattr(quickstart.QuickstartAuthEngine, "reload", recording_reload)

    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://quickstart"))
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme", "beta"),
        database=db_config,
    )
    database = Database(db_config, pool=pool)
    orm = ORM(database)
    app = ArtemisApp(config, database=database, orm=orm)
    attach_quickstart(app)

    async with TestClient(app) as client:
        response = await client.get("/__artemis/ping", tenant="acme")
        assert response.status == 200

    assert calls["seed_config"] is DEFAULT_QUICKSTART_AUTH
    assert sorted(calls["seed_tenants"]) == ["acme", "beta"]
    assert calls["repository_load"] is True
    assert calls["reload_config"] is DEFAULT_QUICKSTART_AUTH
    assert [sorted(entry) for entry in calls.get("schemas", [])]
    assert [sorted(entry) for entry in calls.get("migrations", [])]


@pytest.mark.asyncio
async def test_ensure_tenant_schemas_handles_empty() -> None:
    pool = FakePool()
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://quickstart"))
    database = Database(db_config, pool=pool)
    await ensure_tenant_schemas(database, [])
    assert all("CREATE SCHEMA" not in sql for _, sql, *_ in pool.connection.calls)


@pytest.mark.asyncio
async def test_quickstart_seeder_requires_context() -> None:
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
            quickstart_admin_users=AsyncNoop(),
            quickstart_tenants=AsyncNoop(),
            quickstart_seed_state=SeedState(),
        ),
        tenants=types.SimpleNamespace(quickstart_users=AsyncNoop()),
    )
    config = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="acme",
                name="Acme",
                users=(QuickstartUser(id="usr", email="founder@acme.test"),),
            ),
        ),
        admin=QuickstartAdminRealm(users=()),
    )
    seeder = QuickstartSeeder(cast(ORM, orm_stub))
    with pytest.raises(RuntimeError):
        await seeder.apply(config, tenants={})


@pytest.mark.asyncio
async def test_attach_quickstart_syncs_allowed_tenants_from_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    class StubSeeder:
        def __init__(self, orm: ORM) -> None:
            self.orm = orm

        async def apply(self, config: QuickstartAuthConfig, *, tenants: Mapping[str, TenantContext]) -> bool:
            return True

    class StubRepository:
        def __init__(self, orm: ORM, *, site: str, domain: str) -> None:
            self.orm = orm
            self.site = site
            self.domain = domain

        async def load(self) -> QuickstartAuthConfig | None:
            return QuickstartAuthConfig(
                tenants=(
                    QuickstartTenant(
                        slug="gamma",
                        name="Gamma Corp",
                        users=(
                            QuickstartUser(
                                id="usr_gamma_owner",
                                email="owner@gamma.test",
                                password="gamma-pass",
                            ),
                        ),
                    ),
                ),
                admin=DEFAULT_QUICKSTART_AUTH.admin,
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

    monkeypatch.setattr(quickstart, "QuickstartSeeder", StubSeeder)
    monkeypatch.setattr(quickstart, "QuickstartRepository", StubRepository)
    monkeypatch.setattr(quickstart, "ensure_tenant_schemas", fake_ensure)
    monkeypatch.setattr(MigrationRunner, "run_all", fake_run_all)

    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://quickstart"))
    app_config = AppConfig(site="demo", domain="local.test", allowed_tenants=(), database=db_config)
    database = Database(db_config, pool=pool)
    orm = ORM(database)
    app = ArtemisApp(app_config, database=database, orm=orm)

    attach_quickstart(app)

    assert "gamma" not in app.tenant_resolver.allowed_tenants

    async with TestClient(app) as client:
        response = await client.get("/__artemis/ping", tenant="gamma")
        assert response.status == 200

    assert "gamma" in app.tenant_resolver.allowed_tenants


@pytest.mark.asyncio
async def test_quickstart_repository_returns_none_when_empty() -> None:
    class ListManager:
        def __init__(self) -> None:
            self._items: list[object] = []

        async def list(self, **_: object) -> list[object]:
            return []

    orm_stub = types.SimpleNamespace(
        admin=types.SimpleNamespace(
            quickstart_tenants=ListManager(),
            quickstart_admin_users=ListManager(),
        ),
        tenants=types.SimpleNamespace(
            quickstart_users=types.SimpleNamespace(list=lambda **_: [])
        ),
    )
    repository = QuickstartRepository(cast(ORM, orm_stub), site="demo", domain="local.test")
    assert await repository.load() is None


@pytest.mark.asyncio
async def test_attach_quickstart_with_custom_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class StubSeeder:
        def __init__(self, orm: ORM) -> None:
            calls["init"] = orm

        async def apply(self, config: QuickstartAuthConfig, *, tenants: Mapping[str, TenantContext]) -> bool:
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

    async def recording_reload(self: QuickstartAuthEngine, config: QuickstartAuthConfig) -> None:
        calls["reload"] = config
        await original_reload(self, config)

    original_reload = quickstart.QuickstartAuthEngine.reload
    monkeypatch.setattr(quickstart, "QuickstartSeeder", StubSeeder)
    monkeypatch.setattr(quickstart, "ensure_tenant_schemas", fake_ensure)
    monkeypatch.setattr(MigrationRunner, "run_all", fake_run_all)
    monkeypatch.setattr(quickstart.QuickstartAuthEngine, "reload", recording_reload)

    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://quickstart"))
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme",),
        database=db_config,
    )
    database = Database(db_config, pool=pool)
    orm = ORM(database)
    app = ArtemisApp(config, database=database, orm=orm)
    custom = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="acme",
                name="Acme",
                users=(QuickstartUser(id="usr", email="owner@acme.test"),),
            ),
        ),
        admin=QuickstartAdminRealm(users=()),
    )
    attach_quickstart(app, auth_config=custom)

    async with TestClient(app) as client:
        response = await client.get("/__artemis/ping", tenant="acme")
        assert response.status == 200

    assert calls["config"] is custom
    assert calls["reload"] is custom


def test_load_quickstart_auth_from_env_json() -> None:
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
    env = {"ARTEMIS_QUICKSTART_AUTH": json.dumps(payload)}
    loaded = load_quickstart_auth_from_env(env=env)
    assert loaded is not None
    assert loaded.tenants[0].slug == "env"
    assert loaded.admin.users[0].email == "admin@env.test"


def test_load_quickstart_auth_from_env_file(tmp_path: Path) -> None:
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
    env = {"ARTEMIS_QUICKSTART_AUTH_FILE": str(path)}
    loaded = load_quickstart_auth_from_env(env=env)
    assert loaded is not None
    assert loaded.tenants[0].slug == "file"
    assert loaded.admin.users[0].email == "admin@file.test"


def test_load_quickstart_auth_from_env_invalid() -> None:
    env = {"ARTEMIS_QUICKSTART_AUTH": "{not json}"}
    with pytest.raises(RuntimeError):
        load_quickstart_auth_from_env(env=env)


@pytest.mark.asyncio
async def test_attach_quickstart_uses_repository_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class StubSeeder:
        def __init__(self, orm: ORM) -> None:
            calls["seeder_init"] = orm

        async def apply(self, config: QuickstartAuthConfig, *, tenants: Mapping[str, TenantContext]) -> bool:
            calls.setdefault("seed", []).append(sorted(tenants))
            return True

    class StubRepository:
        def __init__(self, orm: ORM, *, site: str, domain: str) -> None:
            self._orm = orm
            self._site = site
            self._domain = domain

        async def load(self) -> QuickstartAuthConfig | None:
            return QuickstartAuthConfig(
                tenants=(
                    QuickstartTenant(
                        slug="gamma",
                        name="Gamma",
                        users=(QuickstartUser(id="usr", email="owner@gamma.test"),),
                    ),
                ),
                admin=QuickstartAdminRealm(users=()),
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

    async def recording_reload(self: QuickstartAuthEngine, config: QuickstartAuthConfig) -> None:
        calls["reload"] = config
        await original_reload(self, config)

    original_reload = quickstart.QuickstartAuthEngine.reload
    monkeypatch.setattr(quickstart, "QuickstartSeeder", StubSeeder)
    monkeypatch.setattr(quickstart, "QuickstartRepository", StubRepository)
    monkeypatch.setattr(quickstart, "ensure_tenant_schemas", fake_ensure)
    monkeypatch.setattr(MigrationRunner, "run_all", fake_run_all)
    monkeypatch.setattr(quickstart.QuickstartAuthEngine, "reload", recording_reload)

    connection = FakeConnection()
    pool = FakePool(connection)
    db_config = DatabaseConfig(pool=PoolConfig(dsn="postgres://quickstart"))
    config = AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme",),
        database=db_config,
    )
    database = Database(db_config, pool=pool)
    orm = ORM(database)
    app = ArtemisApp(config, database=database, orm=orm)
    attach_quickstart(app)

    async with TestClient(app) as client:
        response = await client.get("/__artemis/ping", tenant="acme")
        assert response.status == 200

    reload_config = calls["reload"]
    assert isinstance(reload_config, QuickstartAuthConfig)
    assert reload_config.tenants[0].slug == "gamma"
    assert any("gamma" in entry for entry in calls.get("schemas", []))
# ------------------------------------------------------------------------------------------- engine unit tests


def _tenant(site: str, domain: str, slug: str, scope: TenantScope) -> TenantContext:
    return TenantContext(tenant=slug, site=site, domain=domain, scope=scope)


@pytest.mark.asyncio
async def test_quickstart_engine_rejects_public_scope() -> None:
    engine = QuickstartAuthEngine(DEFAULT_QUICKSTART_AUTH)
    tenant = _tenant("demo", "local.test", "public", TenantScope.PUBLIC)
    with pytest.raises(HTTPError) as exc:
        await engine.start(tenant, email="user@example.com")
    _assert_error_detail(exc, "login_not_available")


@pytest.mark.asyncio
async def test_quickstart_engine_unknown_user_and_authenticators() -> None:
    engine = QuickstartAuthEngine(DEFAULT_QUICKSTART_AUTH)
    tenant = _tenant("demo", "local.test", "acme", TenantScope.TENANT)
    with pytest.raises(HTTPError) as exc:
        await engine.start(tenant, email="missing@acme.test")
    _assert_error_detail(exc, "unknown_user")

    config = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="gamma",
                name="Gamma",
                users=(QuickstartUser(id="usr_gamma", email="ops@gamma.test"),),
            ),
        ),
        admin=DEFAULT_QUICKSTART_AUTH.admin,
    )
    engine = QuickstartAuthEngine(config)
    tenant = _tenant("demo", "local.test", "gamma", TenantScope.TENANT)
    with pytest.raises(HTTPError) as exc:
        await engine.start(tenant, email="ops@gamma.test")
    _assert_error_detail(exc, "no_authenticators")


@pytest.mark.asyncio
async def test_quickstart_engine_passkey_error_paths() -> None:
    engine = QuickstartAuthEngine(DEFAULT_QUICKSTART_AUTH)
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

    engine = QuickstartAuthEngine(DEFAULT_QUICKSTART_AUTH)
    admin = _tenant("demo", "local.test", "admin", TenantScope.ADMIN)
    start = await engine.start(admin, email="root@admin.test")
    with pytest.raises(HTTPError) as exc:
        await engine.passkey(
            admin,
            PasskeyAttempt(flow_token=start.flow_token, credential_id="beta-passkey", signature="sig"),
        )
    _assert_error_detail(exc, "passkey_not_expected")


@pytest.mark.asyncio
async def test_quickstart_engine_password_paths() -> None:
    engine = QuickstartAuthEngine(DEFAULT_QUICKSTART_AUTH)
    beta = _tenant("demo", "local.test", "beta", TenantScope.TENANT)

    # Password fallback from passkey
    start = await engine.start(beta, email="ops@beta.test")
    response = await engine.password(
        beta, PasswordAttempt(flow_token=start.flow_token, password="beta-password")
    )
    assert response.next is LoginStep.MFA

    # Invalid password
    start = await engine.start(beta, email="ops@beta.test")
    with pytest.raises(HTTPError) as exc:
        await engine.password(beta, PasswordAttempt(flow_token=start.flow_token, password="wrong"))
    _assert_error_detail(exc, "invalid_password")

    # Password not expected once MFA started
    start = await engine.start(beta, email="ops@beta.test")
    user = DEFAULT_QUICKSTART_AUTH.tenants[1].users[0]
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
    config = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="gamma",
                name="Gamma",
                users=(
                    QuickstartUser(
                        id="usr_gamma",
                        email="ops@gamma.test",
                        passkeys=(QuickstartPasskey(credential_id="gamma-passkey", secret="gamma-secret"),),
                    ),
                ),
            ),
        ),
        admin=DEFAULT_QUICKSTART_AUTH.admin,
    )
    engine = QuickstartAuthEngine(config)
    gamma = _tenant("demo", "local.test", "gamma", TenantScope.TENANT)
    start = await engine.start(gamma, email="ops@gamma.test")
    with pytest.raises(HTTPError) as exc:
        await engine.password(gamma, PasswordAttempt(flow_token=start.flow_token, password="irrelevant"))
    _assert_error_detail(exc, "password_not_available")


@pytest.mark.asyncio
async def test_quickstart_engine_mfa_paths() -> None:
    engine = QuickstartAuthEngine(DEFAULT_QUICKSTART_AUTH)
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
async def test_quickstart_engine_success_and_cleanup_paths() -> None:
    config = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="delta",
                name="Delta",
                users=(
                    QuickstartUser(
                        id="usr_delta",
                        email="ops@delta.test",
                        password="delta-pass",
                        passkeys=(QuickstartPasskey(credential_id="delta-passkey", secret="delta-secret"),),
                    ),
                ),
            ),
        ),
        admin=QuickstartAdminRealm(
            users=(
                QuickstartUser(
                    id="adm_demo",
                    email="admin@demo.test",
                    password="demo-admin",
                    passkeys=(QuickstartPasskey(credential_id="adm-passkey", secret="adm-secret"),),
                ),
            ),
        ),
    )
    engine = QuickstartAuthEngine(config)
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
async def test_quickstart_engine_sso_fallback_to_passkey() -> None:
    config = QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(
                slug="epsilon",
                name="Epsilon",
                users=(
                    QuickstartUser(
                        id="usr_epsilon",
                        email="ops@epsilon.test",
                        passkeys=(QuickstartPasskey(credential_id="epsilon-passkey", secret="epsilon-secret"),),
                        sso=QuickstartSsoProvider(
                            slug="okta",
                            kind="saml",
                            display_name="Okta",
                            redirect_url="https://id.epsilon.test/start",
                        ),
                    ),
                ),
            ),
        ),
        admin=DEFAULT_QUICKSTART_AUTH.admin,
    )
    engine = QuickstartAuthEngine(config)
    epsilon = _tenant("demo", "local.test", "epsilon", TenantScope.TENANT)
    start = await engine.start(epsilon, email="ops@epsilon.test")
    assert start.next is LoginStep.SSO
    assert start.fallback is LoginStep.PASSKEY
