"""Developer quickstart routes for OpenAPI, authentication, and tenancy scaffolding."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Final, Iterable, Mapping, Sequence, cast

from msgspec import Struct, convert, field, json

from .application import ArtemisApp
from .authentication import (
    AuthenticationFlowEngine,
    AuthenticationFlowResponse,
    AuthenticationFlowSession,
    AuthenticationFlowUser,
    AuthenticationLoginRecord,
    LoginStep,
)
from .codegen import generate_typescript_client
from .database import Database, _quote_identifier
from .id57 import generate_id57
from .migrations import Migration, MigrationRunner, MigrationScope, create_table_for_model
from .models import SessionLevel
from .openapi import generate_openapi
from .orm import ORM, DatabaseModel, ModelScope, model
from .requests import Request
from .responses import JSONResponse, Response
from .tenancy import TenantContext, TenantScope

_DEV_ENVIRONMENTS: Final[set[str]] = {"development", "dev", "local", "test"}
_DEV_DOMAIN_SUFFIXES: Final[tuple[str, ...]] = (".local", ".localhost", ".test")
_DEV_DOMAINS: Final[set[str]] = {"localhost", "127.0.0.1"}


class QuickstartSsoProvider(Struct, frozen=True):
    """Metadata describing a federated identity provider."""

    slug: str
    kind: str
    display_name: str
    redirect_url: str


class QuickstartPasskey(Struct, frozen=True):
    """Passkey configuration for the quickstart."""

    credential_id: str
    secret: str
    label: str | None = None


class QuickstartUser(Struct, frozen=True):
    """Quickstart user profile with authentication factors."""

    id: str
    email: str
    password: str | None = None
    passkeys: tuple[QuickstartPasskey, ...] = ()
    mfa_code: str | None = None
    sso: QuickstartSsoProvider | None = None


class QuickstartTenant(Struct, frozen=True):
    """Tenant definition used by the quickstart."""

    slug: str
    name: str
    users: tuple[QuickstartUser, ...]


class QuickstartAdminRealm(Struct, frozen=True):
    """Administrative realm definition for the quickstart."""

    users: tuple[QuickstartUser, ...]


QuickstartSession = AuthenticationFlowSession
QuickstartLoginResponse = AuthenticationFlowResponse


class QuickstartPasskeyRecord(Struct, frozen=True):
    """Database representation of a quickstart passkey."""

    credential_id: str
    secret: str
    label: str | None = None


@model(scope=ModelScope.ADMIN, table="quickstart_tenants")
class QuickstartTenantRecord(DatabaseModel):
    """Tenant metadata stored in the admin schema for the quickstart."""

    slug: str
    name: str


@model(scope=ModelScope.ADMIN, table="quickstart_admin_users")
class QuickstartAdminUserRecord(DatabaseModel):
    """Administrative login records for the quickstart."""

    email: str
    password: str | None = None
    passkeys: tuple[QuickstartPasskeyRecord, ...] = field(default_factory=tuple)
    mfa_code: str | None = None


@model(scope=ModelScope.ADMIN, table="quickstart_seed_state")
class QuickstartSeedStateRecord(DatabaseModel):
    """Tracks the last applied quickstart seed fingerprint."""

    key: str
    fingerprint: str


@model(scope=ModelScope.TENANT, table="quickstart_users")
class QuickstartTenantUserRecord(DatabaseModel):
    """Tenant-scoped login records for the quickstart."""

    email: str
    password: str | None = None
    passkeys: tuple[QuickstartPasskeyRecord, ...] = field(default_factory=tuple)
    mfa_code: str | None = None
    sso_provider: QuickstartSsoProvider | None = None


class QuickstartAuthConfig(Struct, frozen=True):
    """Configuration for the quickstart authentication engine."""

    tenants: tuple[QuickstartTenant, ...]
    admin: QuickstartAdminRealm
    session_ttl_seconds: int = 3600
    flow_ttl_seconds: int = 600
    max_attempts: int = 5


class LoginStartRequest(Struct, frozen=True):
    """Payload for beginning an authentication flow."""

    email: str


class PasskeyAttempt(Struct, frozen=True):
    """Payload for signing in with a passkey."""

    flow_token: str
    credential_id: str
    signature: str


class PasswordAttempt(Struct, frozen=True):
    """Payload for signing in with a password."""

    flow_token: str
    password: str


class MfaAttempt(Struct, frozen=True):
    """Payload for completing an MFA challenge."""

    flow_token: str
    code: str


def quickstart_migrations() -> tuple[Migration, ...]:
    """Return the migrations required to persist quickstart data."""

    return (
        Migration(
            name="quickstart_admin_tables",
            scope=MigrationScope.ADMIN,
            operations=(
                create_table_for_model(QuickstartTenantRecord),
                create_table_for_model(QuickstartAdminUserRecord),
                create_table_for_model(QuickstartSeedStateRecord),
            ),
        ),
        Migration(
            name="quickstart_tenant_tables",
            scope=MigrationScope.TENANT,
            operations=(create_table_for_model(QuickstartTenantUserRecord),),
        ),
    )


async def ensure_tenant_schemas(database: Database, tenants: Sequence[TenantContext]) -> None:
    """Create tenant schemas for the quickstart if they do not already exist."""

    schemas = {
        database.config.schema_for_tenant(tenant)
        for tenant in tenants
    }
    async with database.connection(schema=database.config.admin_schema) as connection:
        for schema in sorted(schemas):
            await connection.execute(
                f"CREATE SCHEMA IF NOT EXISTS {_quote_identifier(schema)}"
            )


class QuickstartSeeder:
    """Populate the database with quickstart identities."""

    _STATE_KEY: Final[str] = "quickstart_auth"

    def __init__(self, orm: ORM, *, clock: Callable[[], datetime] | None = None) -> None:
        self._orm = orm
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    async def apply(
        self,
        config: QuickstartAuthConfig,
        *,
        tenants: Mapping[str, TenantContext],
    ) -> bool:
        fingerprint = self._fingerprint(config)
        state_manager = self._orm.admin.quickstart_seed_state
        existing_state = await state_manager.get(filters={"key": self._STATE_KEY})
        if existing_state and existing_state.fingerprint == fingerprint:
            return False

        admin_manager = self._orm.admin.quickstart_admin_users
        await admin_manager.delete(filters=None)
        for user in config.admin.users:
            await admin_manager.create(
                QuickstartAdminUserRecord(
                    id=user.id,
                    email=user.email,
                    password=user.password,
                    passkeys=self._passkeys_to_records(user.passkeys),
                    mfa_code=user.mfa_code,
                )
            )

        tenant_manager = self._orm.admin.quickstart_tenants
        await tenant_manager.delete(filters=None)
        for tenant in config.tenants:
            await tenant_manager.create(
                QuickstartTenantRecord(slug=tenant.slug, name=tenant.name)
            )
            context = tenants.get(tenant.slug)
            if context is None:
                raise RuntimeError(
                    f"Tenant '{tenant.slug}' is missing from the quickstart tenant mapping"
                )
            user_manager = self._orm.tenants.quickstart_users
            await user_manager.delete(tenant=context, filters=None)
            for user in tenant.users:
                await user_manager.create(
                    QuickstartTenantUserRecord(
                        id=user.id,
                        email=user.email,
                        password=user.password,
                        passkeys=self._passkeys_to_records(user.passkeys),
                        mfa_code=user.mfa_code,
                        sso_provider=user.sso,
                    ),
                    tenant=context,
                )

        await self._record_state(state_manager, existing_state, fingerprint)
        return True

    async def _record_state(
        self,
        state_manager: Any,
        existing_state: QuickstartSeedStateRecord | None,
        fingerprint: str,
    ) -> None:
        now = self._clock()
        if existing_state is None:
            await state_manager.create(
                QuickstartSeedStateRecord(
                    key=self._STATE_KEY,
                    fingerprint=fingerprint,
                    created_at=now,
                    updated_at=now,
                )
            )
            return
        await state_manager.update(
            {
                "fingerprint": fingerprint,
                "updated_at": now,
            },
            filters={"id": existing_state.id},
        )

    @staticmethod
    def _passkeys_to_records(
        passkeys: tuple[QuickstartPasskey, ...]
    ) -> tuple[QuickstartPasskeyRecord, ...]:
        return tuple(
            QuickstartPasskeyRecord(
                credential_id=item.credential_id,
                secret=item.secret,
                label=item.label,
            )
            for item in passkeys
        )

    @staticmethod
    def _fingerprint(config: QuickstartAuthConfig) -> str:
        payload = json.encode(config)
        return hashlib.sha256(payload).hexdigest()


class QuickstartRepository:
    """Load quickstart identities from the database."""

    def __init__(self, orm: ORM, *, site: str, domain: str) -> None:
        self._orm = orm
        self._site = site
        self._domain = domain

    async def load(self) -> QuickstartAuthConfig | None:
        tenants = await self._orm.admin.quickstart_tenants.list(order_by=("slug",))
        admins = await self._orm.admin.quickstart_admin_users.list(order_by=("email",))
        if not tenants and not admins:
            return None
        tenant_configs = []
        for tenant in tenants:
            context = TenantContext(
                tenant=tenant.slug,
                site=self._site,
                domain=self._domain,
                scope=TenantScope.TENANT,
            )
            users = await self._orm.tenants.quickstart_users.list(
                tenant=context, order_by=("email",)
            )
            tenant_configs.append(
                QuickstartTenant(
                    slug=tenant.slug,
                    name=tenant.name,
                    users=tuple(self._convert_user(user) for user in users),
                )
            )
        admin_users = tuple(self._convert_admin(user) for user in admins)
        admin_realm = QuickstartAdminRealm(users=admin_users)
        return QuickstartAuthConfig(
            tenants=tuple(tenant_configs),
            admin=admin_realm,
            session_ttl_seconds=DEFAULT_QUICKSTART_AUTH.session_ttl_seconds,
            flow_ttl_seconds=DEFAULT_QUICKSTART_AUTH.flow_ttl_seconds,
            max_attempts=DEFAULT_QUICKSTART_AUTH.max_attempts,
        )

    @staticmethod
    def _convert_user(record: QuickstartTenantUserRecord) -> QuickstartUser:
        return QuickstartUser(
            id=record.id,
            email=record.email,
            password=record.password,
            passkeys=QuickstartRepository._records_to_passkeys(record.passkeys),
            mfa_code=record.mfa_code,
            sso=record.sso_provider,
        )

    @staticmethod
    def _convert_admin(record: QuickstartAdminUserRecord) -> QuickstartUser:
        return QuickstartUser(
            id=record.id,
            email=record.email,
            password=record.password,
            passkeys=QuickstartRepository._records_to_passkeys(record.passkeys),
            mfa_code=record.mfa_code,
        )

    @staticmethod
    def _records_to_passkeys(
        records: tuple[QuickstartPasskeyRecord, ...]
    ) -> tuple[QuickstartPasskey, ...]:
        return tuple(
            QuickstartPasskey(
                credential_id=record.credential_id,
                secret=record.secret,
                label=record.label,
            )
            for record in records
        )


def _read_env_blob(name: str, env: Mapping[str, str]) -> str | None:
    file_key = f"{name}_FILE"
    path = env.get(file_key)
    if path:
        try:
            return Path(path).read_text(encoding="utf-8")
        except FileNotFoundError as exc:  # pragma: no cover - validated in integration tests
            raise RuntimeError(
                f"Quickstart configuration file at '{path}' not found"
            ) from exc
    value = env.get(name)
    if value:
        return value
    return None


def load_quickstart_auth_from_env(
    *, env: Mapping[str, str] | None = None
) -> QuickstartAuthConfig | None:
    """Decode :class:`QuickstartAuthConfig` material from environment variables."""

    source = _read_env_blob("ARTEMIS_QUICKSTART_AUTH", env or os.environ)
    if source is None:
        return None
    try:
        payload = json.decode(source)
    except Exception as exc:  # pragma: no cover - defensive surface
        raise RuntimeError("Failed to decode ARTEMIS_QUICKSTART_AUTH as JSON") from exc
    try:
        return convert(payload, type=QuickstartAuthConfig)
    except Exception as exc:  # pragma: no cover - defensive surface
        raise RuntimeError("Invalid quickstart auth configuration in environment") from exc


class QuickstartAuthEngine(AuthenticationFlowEngine[AuthenticationFlowUser, QuickstartSession]):
    """Quickstart authentication engine built on the shared flow orchestration."""

    def __init__(self, config: QuickstartAuthConfig) -> None:
        super().__init__(
            flow_ttl_seconds=config.flow_ttl_seconds,
            session_ttl_seconds=config.session_ttl_seconds,
            max_attempts=config.max_attempts,
        )
        self.config = config
        self._apply_config(config)

    async def reload(self, config: QuickstartAuthConfig) -> None:
        """Replace the engine state with ``config``."""

        async with self._lock:
            self.config = config
            self._apply_config(config)

    def _apply_config(self, config: QuickstartAuthConfig) -> None:
        records: list[AuthenticationLoginRecord[AuthenticationFlowUser]] = []
        for tenant in config.tenants:
            for user in tenant.users:
                records.append(
                    AuthenticationLoginRecord(
                        scope=TenantScope.TENANT,
                        tenant=tenant.slug,
                        user=cast(AuthenticationFlowUser, user),
                    )
                )
        for user in config.admin.users:
            records.append(
                AuthenticationLoginRecord(
                    scope=TenantScope.ADMIN,
                    tenant="admin",
                    user=cast(AuthenticationFlowUser, user),
                )
            )
        self.flow_ttl_seconds = config.flow_ttl_seconds
        self.session_ttl_seconds = config.session_ttl_seconds
        self.max_attempts = config.max_attempts
        self.reset(records)

    def _issue_session(self, flow: Any, level: SessionLevel) -> QuickstartSession:
        return QuickstartSession(
            token=f"qs_{generate_id57()}",
            user_id=flow.user.id,
            scope=flow.scope,
            level=level,
            expires_in=self.session_ttl_seconds,
        )


def _default_auth_config() -> QuickstartAuthConfig:
    """Return the built-in quickstart auth configuration."""

    acme_owner = QuickstartUser(
        id="usr_acme_owner",
        email="founder@acme.test",
        sso=QuickstartSsoProvider(
            slug="okta",
            kind="saml",
            display_name="Okta",
            redirect_url="https://id.acme.test/sso/start",
        ),
    )
    beta_ops = QuickstartUser(
        id="usr_beta_ops",
        email="ops@beta.test",
        password="beta-password",
        passkeys=(
            QuickstartPasskey(
                credential_id="beta-passkey",
                secret="beta-passkey-secret",
                label="YubiKey 5",
            ),
        ),
        mfa_code="654321",
    )
    admin_root = QuickstartUser(
        id="adm_root",
        email="root@admin.test",
        password="admin-password",
        mfa_code="123456",
    )
    return QuickstartAuthConfig(
        tenants=(
            QuickstartTenant(slug="acme", name="Acme Rockets", users=(acme_owner,)),
            QuickstartTenant(slug="beta", name="Beta Industries", users=(beta_ops,)),
        ),
        admin=QuickstartAdminRealm(users=(admin_root,)),
    )


DEFAULT_QUICKSTART_AUTH: Final[QuickstartAuthConfig] = _default_auth_config()


def attach_quickstart(
    app: ArtemisApp,
    *,
    base_path: str = "/__artemis",
    environment: str | None = None,
    allow_production: bool = False,
    auth_config: QuickstartAuthConfig | None = None,
) -> None:
    """Attach development-only routes for OpenAPI, TypeScript clients, and login orchestration."""

    env = (environment or os.getenv("ARTEMIS_ENV") or "development").lower()
    domain = app.config.domain.lower()
    is_dev_env = env in _DEV_ENVIRONMENTS
    is_dev_domain = domain in _DEV_DOMAINS or any(domain.endswith(suffix) for suffix in _DEV_DOMAIN_SUFFIXES)
    if not allow_production and not (is_dev_env or is_dev_domain):
        raise RuntimeError("Quickstart routes are only available in development environments")

    normalized = base_path.strip()
    if not normalized:
        normalized = ""
    else:
        normalized = "/" + normalized.strip("/")

    ping_path = f"{normalized}/ping" if normalized else "/ping"
    openapi_path = f"{normalized}/openapi.json" if normalized else "/openapi.json"
    client_path = f"{normalized}/client.ts" if normalized else "/client.ts"
    login_start_path = f"{normalized}/auth/login/start" if normalized else "/auth/login/start"
    passkey_path = f"{normalized}/auth/login/passkey" if normalized else "/auth/login/passkey"
    password_path = f"{normalized}/auth/login/password" if normalized else "/auth/login/password"
    mfa_path = f"{normalized}/auth/login/mfa" if normalized else "/auth/login/mfa"

    env_auth_config = load_quickstart_auth_from_env()
    seed_hint = auth_config or env_auth_config or DEFAULT_QUICKSTART_AUTH

    def _sync_allowed_tenants(config: QuickstartAuthConfig) -> None:
        resolver = app.tenant_resolver
        resolver.allowed_tenants.update(tenant.slug for tenant in config.tenants)
        resolver.allowed_tenants.discard(app.config.admin_subdomain)
        resolver.allowed_tenants.discard(app.config.marketing_tenant)

    _sync_allowed_tenants(seed_hint)

    engine = QuickstartAuthEngine(seed_hint)
    app.dependencies.provide(QuickstartAuthEngine, lambda: engine)

    if app.database and app.orm:
        database = cast(Database, app.database)
        orm = cast(ORM, app.orm)
        tenant_slugs = set(app.config.allowed_tenants)
        tenant_slugs.update(tenant.slug for tenant in seed_hint.tenants)
        tenant_slugs.discard(app.config.admin_subdomain)
        tenant_slugs.discard(app.config.marketing_tenant)
        tenants_map: dict[str, TenantContext] = {
            slug: TenantContext(
                tenant=slug,
                site=app.config.site,
                domain=app.config.domain,
                scope=TenantScope.TENANT,
            )
            for slug in sorted(tenant_slugs)
        }
        runner = MigrationRunner(
            database,
            migrations=quickstart_migrations(),
            tenant_provider=lambda: list(tenants_map.values()),
        )
        seeder = QuickstartSeeder(orm)
        repository = QuickstartRepository(
            orm, site=app.config.site, domain=app.config.domain
        )

        async def _ensure_contexts_for(slugs: Iterable[str]) -> None:
            missing = sorted(set(slugs) - tenants_map.keys())
            for slug in missing:
                tenants_map[slug] = TenantContext(
                    tenant=slug,
                    site=app.config.site,
                    domain=app.config.domain,
                    scope=TenantScope.TENANT,
                )
            contexts = list(tenants_map.values())
            await ensure_tenant_schemas(database, contexts)
            await runner.run_all(tenants=contexts)

        async def _bootstrap_quickstart() -> None:
            await _ensure_contexts_for(tenants_map.keys())
            config_to_load: QuickstartAuthConfig
            source_config = auth_config or env_auth_config
            if source_config is not None:
                config_to_load = source_config
                await _ensure_contexts_for(
                    tenant.slug for tenant in config_to_load.tenants
                )
                await seeder.apply(config_to_load, tenants=tenants_map)
            else:
                loaded = await repository.load()
                if loaded is None:
                    config_to_load = DEFAULT_QUICKSTART_AUTH
                    await _ensure_contexts_for(
                        tenant.slug for tenant in config_to_load.tenants
                    )
                    await seeder.apply(config_to_load, tenants=tenants_map)
                else:
                    config_to_load = loaded
                    await _ensure_contexts_for(
                        tenant.slug for tenant in config_to_load.tenants
                    )
            await engine.reload(config_to_load)
            _sync_allowed_tenants(config_to_load)

        app.on_startup(_bootstrap_quickstart)

    @app.get(ping_path, name="quickstart_ping")
    async def quickstart_ping() -> str:
        return "pong"

    @app.get(openapi_path, name="quickstart_openapi")
    async def quickstart_openapi() -> Response:
        spec = generate_openapi(app)
        return JSONResponse(spec)

    @app.get(client_path, name="quickstart_client")
    async def quickstart_client() -> Response:
        spec = generate_openapi(app)
        source = generate_typescript_client(spec)
        return Response(
            headers=(("content-type", "application/typescript"),),
            body=source.encode("utf-8"),
        )

    @app.post(login_start_path, name="quickstart_login_start")
    async def quickstart_login_start(
        request: Request, payload: LoginStartRequest, engine: QuickstartAuthEngine
    ) -> Response:
        result = await engine.start(request.tenant, email=payload.email)
        return JSONResponse(result)

    @app.post(passkey_path, name="quickstart_login_passkey")
    async def quickstart_login_passkey(
        request: Request, payload: PasskeyAttempt, engine: QuickstartAuthEngine
    ) -> Response:
        result = await engine.passkey(request.tenant, payload)
        return JSONResponse(result)

    @app.post(password_path, name="quickstart_login_password")
    async def quickstart_login_password(
        request: Request, payload: PasswordAttempt, engine: QuickstartAuthEngine
    ) -> Response:
        result = await engine.password(request.tenant, payload)
        return JSONResponse(result)

    @app.post(mfa_path, name="quickstart_login_mfa")
    async def quickstart_login_mfa(
        request: Request, payload: MfaAttempt, engine: QuickstartAuthEngine
    ) -> Response:
        result = await engine.mfa(request.tenant, payload)
        return JSONResponse(result)


__all__ = [
    "DEFAULT_QUICKSTART_AUTH",
    "LoginStep",
    "MfaAttempt",
    "PasskeyAttempt",
    "PasswordAttempt",
    "QuickstartAdminRealm",
    "QuickstartAdminUserRecord",
    "QuickstartAuthConfig",
    "QuickstartAuthEngine",
    "QuickstartLoginResponse",
    "QuickstartPasskey",
    "QuickstartPasskeyRecord",
    "QuickstartRepository",
    "QuickstartSeedStateRecord",
    "QuickstartSeeder",
    "QuickstartSession",
    "QuickstartSsoProvider",
    "QuickstartTenant",
    "QuickstartTenantRecord",
    "QuickstartTenantUserRecord",
    "QuickstartUser",
    "attach_quickstart",
    "ensure_tenant_schemas",
    "load_quickstart_auth_from_env",
    "quickstart_migrations",
]
