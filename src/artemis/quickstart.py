"""Developer quickstart routes for OpenAPI, authentication, and tenancy scaffolding."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Final,
    Iterable,
    Literal,
    Mapping,
    Protocol,
    Sequence,
    cast,
)

import rure
from msgspec import Struct, convert, field, json, to_builtins

from .application import ArtemisApp
from .authentication import (
    AuthenticationFlowEngine,
    AuthenticationFlowResponse,
    AuthenticationFlowSession,
    AuthenticationFlowUser,
    AuthenticationLoginRecord,
    LoginStep,
)
from .chatops import (
    ChatMessage,
    ChatOpsCommandBinding,
    ChatOpsCommandContext,
    ChatOpsCommandResolutionError,
    ChatOpsConfig,
    ChatOpsError,
    ChatOpsInvocationError,
    ChatOpsService,
    ChatOpsSlashCommand,
    SlackWebhookConfig,
    parse_slash_command_args,
)
from .codegen import generate_typescript_client
from .database import Database, _quote_identifier
from .domain.quickstart_services import (
    QuickstartAuditService,
    QuickstartDelegationService,
    QuickstartRbacService,
    QuickstartTileService,
    build_cedar_engine,
)
from .domain.services import (
    AuditLogExportQuery,
    AuditService,
    DelegationGrant,
    DelegationService,
    PermissionSetCreate,
    RbacService,
    RoleAssignment,
    TileCreate,
    TilePermissions,
    TileService,
    TileUpdate,
)
from .exceptions import HTTPError
from .http import Status
from .id57 import generate_id57
from .migrations import Migration, MigrationRunner, MigrationScope, create_table_for_model
from .models import (
    AdminAuditLogEntry,
    AdminRoleAssignment,
    BillingRecord,
    BillingStatus,
    DashboardTile,
    DashboardTilePermission,
    Permission,
    Role,
    SessionLevel,
    SupportTicket,
    SupportTicketKind,
    SupportTicketStatus,
    SupportTicketUpdate,
    TenantAuditLogEntry,
    TenantSupportTicket,
    WorkspacePermissionDelegation,
    WorkspacePermissionSet,
    WorkspaceRoleAssignment,
)
from .openapi import generate_openapi
from .orm import ORM, DatabaseModel, ModelScope, model
from .rbac import CedarEngine
from .requests import Request
from .responses import JSONResponse, Response
from .tenancy import TenantContext, TenantScope

_DEV_ENVIRONMENTS: Final[set[str]] = {"development", "dev", "local", "test"}
_DEV_DOMAIN_SUFFIXES: Final[tuple[str, ...]] = (".local", ".localhost", ".test")
_DEV_DOMAINS: Final[set[str]] = {"localhost", "127.0.0.1"}

if TYPE_CHECKING:
    class RureRegex(Protocol):
        def is_match(self, value: str) -> bool:  # pragma: no cover - typing helper
            ...


else:  # pragma: no cover - runtime alias derived from compiled pattern
    RureRegex = type(rure.compile("demo"))


_TENANT_SLUG_PATTERN: Final[RureRegex] = cast(
    "RureRegex", rure.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
)


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


class QuickstartChatOpsNotificationChannels(Struct, frozen=True):
    """Channel overrides for ChatOps notifications."""

    tenant_created: str | None = None
    billing_updated: str | None = None
    subscription_past_due: str | None = None
    trial_extended: str | None = None
    support_ticket_created: str | None = None
    support_ticket_updated: str | None = None


class QuickstartSlashCommand(Struct, frozen=True):
    """ChatOps command metadata for the quickstart surface."""

    name: str
    action: Literal[
        "create_tenant",
        "extend_trial",
        "tenant_metrics",
        "system_diagnostics",
        "ticket_update",
    ]
    description: str
    visibility: Literal["admin", "public"] = "admin"
    aliases: tuple[str, ...] = ()


def _default_slash_commands() -> tuple[QuickstartSlashCommand, ...]:
    return (
        QuickstartSlashCommand(
            name="create-tenant",
            action="create_tenant",
            description="Provision a new tenant from Slack.",
            aliases=("quickstart-create-tenant",),
        ),
        QuickstartSlashCommand(
            name="extend-trial",
            action="extend_trial",
            description="Extend a tenant's trial period from Slack.",
            aliases=("quickstart-extend-trial",),
        ),
        QuickstartSlashCommand(
            name="tenant-metrics",
            action="tenant_metrics",
            description="Summarize tenant metrics for administrators.",
            aliases=("quickstart-tenant-metrics",),
        ),
        QuickstartSlashCommand(
            name="system-diagnostics",
            action="system_diagnostics",
            description="Display quickstart diagnostics and health checks.",
            aliases=("quickstart-system-diagnostics",),
        ),
        QuickstartSlashCommand(
            name="ticket-update",
            action="ticket_update",
            description="Post an update to a customer support ticket.",
            aliases=("quickstart-ticket-update",),
        ),
    )


class QuickstartChatOpsSettings(Struct, frozen=True):
    """Runtime ChatOps configuration maintained by the quickstart routes."""

    enabled: bool = False
    webhook: SlackWebhookConfig | None = None
    notifications: QuickstartChatOpsNotificationChannels = field(
        default_factory=QuickstartChatOpsNotificationChannels
    )
    slash_commands: tuple[QuickstartSlashCommand, ...] = field(
        default_factory=_default_slash_commands
    )
    bot_user_id: str | None = None
    admin_workspace: str | None = None


class QuickstartAuditLogQuery(Struct, frozen=True, omit_defaults=True):
    """Query parameters used by audit log routes."""

    actor: str | None = None
    action: str | None = None
    entity: str | None = None
    from_time: datetime | None = field(name="from", default=None)
    to_time: datetime | None = field(name="to", default=None)
    format: Literal["csv", "json"] | None = None


class QuickstartSlashCommandInvocation(Struct, frozen=True):
    """Payload delivered from ChatOps slash command integrations."""

    text: str
    user_id: str
    command: str | None = None
    user_name: str | None = None
    channel_id: str | None = None
    workspace_id: str | None = None


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


@model(scope=ModelScope.ADMIN, table="quickstart_trial_extensions")
class QuickstartTrialExtensionRecord(DatabaseModel):
    """Audit record describing ChatOps-driven trial extensions."""

    tenant_slug: str
    extended_days: int
    requested_by: str
    note: str | None = None


QuickstartSupportTicketUpdateLog = SupportTicketUpdate
QuickstartSupportTicketRecord = SupportTicket
QuickstartTenantSupportTicketRecord = TenantSupportTicket


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


class BillingCreateRequest(Struct, frozen=True):
    """Payload for creating a billing record via the quickstart routes."""

    customer_id: str
    plan_code: str
    status: BillingStatus
    amount_due_cents: int
    currency: str
    cycle_start: datetime
    cycle_end: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


class QuickstartTenantCreateRequest(Struct, frozen=True):
    """Payload for creating a tenant through the quickstart API."""

    slug: str
    name: str


class QuickstartSupportTicketRequest(Struct, frozen=True):
    """Tenant-facing payload for creating a support ticket."""

    subject: str
    message: str
    kind: Literal["general", "feedback", "issue"]


class QuickstartSupportTicketUpdateRequest(Struct, frozen=True):
    """Administrative payload for updating a support ticket."""

    status: Literal["open", "responded", "resolved"]
    note: str | None = None


def quickstart_migrations() -> tuple[Migration, ...]:
    """Return the migrations required to persist quickstart data."""

    return (
        Migration(
            name="quickstart_admin_tables",
            scope=MigrationScope.ADMIN,
            operations=(
                create_table_for_model(AdminAuditLogEntry),
                create_table_for_model(BillingRecord),
                create_table_for_model(QuickstartTenantRecord),
                create_table_for_model(QuickstartAdminUserRecord),
                create_table_for_model(QuickstartSeedStateRecord),
                create_table_for_model(QuickstartTrialExtensionRecord),
                create_table_for_model(Role),
                create_table_for_model(Permission),
                create_table_for_model(AdminRoleAssignment),
                create_table_for_model(SupportTicket),
            ),
        ),
        Migration(
            name="quickstart_tenant_tables",
            scope=MigrationScope.TENANT,
            operations=(
                create_table_for_model(QuickstartTenantUserRecord),
                create_table_for_model(TenantSupportTicket),
                create_table_for_model(TenantAuditLogEntry),
                create_table_for_model(DashboardTile),
                create_table_for_model(DashboardTilePermission),
                create_table_for_model(WorkspacePermissionSet),
                create_table_for_model(WorkspaceRoleAssignment),
                create_table_for_model(WorkspacePermissionDelegation),
            ),
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


class QuickstartChatOpsControlPlane:
    """Centralizes ChatOps configuration, normalization, and invocation handling."""

    def __init__(
        self,
        app: ArtemisApp,
        settings: QuickstartChatOpsSettings,
        *,
        command_pattern: RureRegex,
    ) -> None:
        self._app = app
        self._settings = settings
        self._command_pattern = command_pattern
        self._action_bindings: dict[str, str] = {}
        self._binding_actions: dict[str, str] = {}

    @property
    def settings(self) -> QuickstartChatOpsSettings:
        return self._settings

    def register_action_binding(self, action: str, binding_name: str) -> None:
        self._action_bindings[action] = binding_name

    def configure(self, settings: QuickstartChatOpsSettings) -> None:
        """Apply ``settings`` to the ChatOps service and command registry."""

        normalized_commands = self.normalize_commands(settings.slash_commands or _default_slash_commands())
        self._settings = QuickstartChatOpsSettings(
            enabled=settings.enabled,
            webhook=settings.webhook,
            notifications=settings.notifications,
            slash_commands=normalized_commands,
            bot_user_id=settings.bot_user_id,
            admin_workspace=settings.admin_workspace,
        )
        config = ChatOpsConfig(enabled=self._settings.enabled, default=self._settings.webhook)
        self._app.chatops = ChatOpsService(config, observability=self._app.observability)
        self._app.dependencies.provide(ChatOpsService, lambda: self._app.chatops)
        self._apply_command_bindings()

    def normalize_command_definition(self, command: QuickstartSlashCommand) -> QuickstartSlashCommand:
        normalized_name = self._app.chatops.normalize_command_token(command.name)
        if not normalized_name or not self._command_pattern.is_match(normalized_name):
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_command_name"})
        normalized_aliases: list[str] = []
        seen_aliases = {normalized_name}
        for alias in command.aliases:
            normalized_alias = self._app.chatops.normalize_command_token(alias)
            if not normalized_alias or not self._command_pattern.is_match(normalized_alias):
                raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_command_name"})
            if normalized_alias in seen_aliases:
                continue
            normalized_aliases.append(normalized_alias)
            seen_aliases.add(normalized_alias)
        return QuickstartSlashCommand(
            name=normalized_name,
            action=command.action,
            description=command.description,
            visibility=command.visibility,
            aliases=tuple(normalized_aliases),
        )

    def normalize_commands(
        self, commands: Iterable[QuickstartSlashCommand]
    ) -> tuple[QuickstartSlashCommand, ...]:
        normalized: list[QuickstartSlashCommand] = []
        seen: set[str] = set()
        for command in commands:
            normalized_command = self.normalize_command_definition(command)
            for token in (normalized_command.name, *normalized_command.aliases):
                if token in seen:
                    raise HTTPError(Status.BAD_REQUEST, {"detail": "duplicate_command"})
                seen.add(token)
            normalized.append(normalized_command)
        return tuple(normalized)

    def serialize_settings(self) -> dict[str, Any]:
        payload = dict(to_builtins(self._settings))
        if self._settings.admin_workspace is None:
            payload["slash_commands"] = [
                command
                for command in payload.get("slash_commands", [])
                if command.get("visibility") != "admin"
            ]
        return payload

    def _apply_command_bindings(self) -> None:
        for command in self._settings.slash_commands:
            binding_name = self._action_bindings.get(command.action)
            if not binding_name:
                continue
            try:
                binding = self._app.chatops_commands.binding_by_name(binding_name)
            except LookupError:
                continue
            updated_command = ChatOpsSlashCommand(
                name=command.name,
                description=command.description,
                visibility=command.visibility,
                aliases=command.aliases,
            )
            self._binding_actions[binding_name] = command.action
            self._app.chatops_commands.register(
                ChatOpsCommandBinding(
                    command=updated_command,
                    handler=binding.handler,
                    name=binding.name,
                )
            )

    def channel_for_event(self, event: str) -> str | None:
        mapping = {
            "tenant_created": self._settings.notifications.tenant_created,
            "billing_updated": self._settings.notifications.billing_updated,
            "subscription_past_due": self._settings.notifications.subscription_past_due,
            "trial_extended": self._settings.notifications.trial_extended,
            "support_ticket_created": self._settings.notifications.support_ticket_created,
            "support_ticket_updated": self._settings.notifications.support_ticket_updated,
        }
        return mapping.get(event)

    async def notify(
        self,
        event: str,
        message: str,
        *,
        extra: Mapping[str, Any] | None = None,
        channel: str | None = None,
    ) -> None:
        if not self._settings.enabled or self._settings.webhook is None:
            return
        destination = channel or self.channel_for_event(event)
        builtins_extra = dict(to_builtins(extra or {}))
        chat_message = ChatMessage(text=message, channel=destination, extra=builtins_extra)
        admin_context = self._app.tenant_resolver.context_for(self._app.config.admin_subdomain, TenantScope.ADMIN)
        try:
            await self._app.chatops.send(admin_context, chat_message)
        except ChatOpsError:
            return

    def resolve_invocation(
        self,
        request: Request,
        payload: QuickstartSlashCommandInvocation,
    ) -> tuple[ChatOpsCommandBinding, dict[str, str], str]:
        command_name, arg_text = self._app.chatops.extract_command_from_invocation(
            payload,
            bot_user_id=self._settings.bot_user_id,
        )
        available_commands: list[ChatOpsSlashCommand] = []
        for command in self._settings.slash_commands:
            binding_name = self._action_bindings.get(command.action)
            if not binding_name:
                continue
            try:
                binding = self._app.chatops_commands.binding_by_name(binding_name)
            except LookupError:
                continue
            available_commands.append(binding.command)
        resolved_command = self._app.chatops.resolve_slash_command(
            command_name,
            available_commands,
            tenant=request.tenant,
            workspace_id=getattr(payload, "workspace_id", None),
            admin_workspace=self._settings.admin_workspace,
        )
        binding = self._app.chatops_commands.binding_for(resolved_command)
        args = parse_slash_command_args(arg_text)
        actor = getattr(payload, "user_name", None) or getattr(payload, "user_id", "unknown")
        return binding, args, actor

    def action_for_binding(self, binding: ChatOpsCommandBinding) -> str | None:
        return self._binding_actions.get(binding.name)


class QuickstartAdminControlPlane:
    """Encapsulates admin operations for the quickstart bundle."""

    def __init__(
        self,
        app: ArtemisApp,
        *,
        slug_normalizer: Callable[[str], str],
        slug_pattern: RureRegex,
        ensure_contexts: Callable[[Iterable[str]], Awaitable[None]],
        chatops: QuickstartChatOpsControlPlane,
        sync_allowed_tenants: Callable[[QuickstartAuthConfig], None],
    ) -> None:
        self._app = app
        self._normalize_slug = slug_normalizer
        self._slug_pattern = slug_pattern
        self._ensure_contexts = ensure_contexts
        self._chatops = chatops
        self._sync_allowed_tenants = sync_allowed_tenants
        self._reserved_slugs = {app.config.admin_subdomain, app.config.marketing_tenant}

    async def create_tenant_from_inputs(
        self,
        slug: str,
        name: str,
        *,
        orm: ORM,
        engine: QuickstartAuthEngine,
        actor: str,
        source: str,
    ) -> QuickstartTenantRecord:
        normalized_slug = self._normalize_slug(slug)
        cleaned_name = name.strip()
        if not normalized_slug or not self._slug_pattern.is_match(normalized_slug):
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_slug"})
        if not cleaned_name:
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_name"})
        if normalized_slug in self._reserved_slugs:
            raise HTTPError(409, {"detail": "slug_reserved"})
        existing = await orm.admin.quickstart_tenants.get(filters={"slug": normalized_slug})
        if existing is not None:
            raise HTTPError(409, {"detail": "tenant_exists"})
        await self._ensure_contexts([normalized_slug])
        record = await orm.admin.quickstart_tenants.create(
            {"slug": normalized_slug, "name": cleaned_name}
        )
        tenants_config = [tenant for tenant in engine.config.tenants if tenant.slug != normalized_slug]
        tenants_config.append(QuickstartTenant(slug=normalized_slug, name=cleaned_name, users=()))
        updated_config = QuickstartAuthConfig(
            tenants=tuple(sorted(tenants_config, key=lambda item: item.slug)),
            admin=engine.config.admin,
            session_ttl_seconds=engine.config.session_ttl_seconds,
            flow_ttl_seconds=engine.config.flow_ttl_seconds,
            max_attempts=engine.config.max_attempts,
        )
        await engine.reload(updated_config)
        self._sync_allowed_tenants(updated_config)
        await self._chatops.notify(
            "tenant_created",
            f"Tenant '{cleaned_name}' ({normalized_slug}) provisioned via {source} by {actor}",
            extra={
                "slug": normalized_slug,
                "name": cleaned_name,
                "actor": actor,
                "source": source,
            },
        )
        return cast(QuickstartTenantRecord, record)

    async def grant_trial_extension(
        self,
        tenant_slug: str,
        days: int,
        *,
        note: str | None,
        actor: str,
        orm: ORM,
    ) -> QuickstartTrialExtensionRecord:
        normalized_slug = self._normalize_slug(tenant_slug)
        if not normalized_slug or not self._slug_pattern.is_match(normalized_slug):
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_slug"})
        if days <= 0:
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_days"})
        tenant_record = await orm.admin.quickstart_tenants.get(filters={"slug": normalized_slug})
        if tenant_record is None:
            raise HTTPError(Status.NOT_FOUND, {"detail": "tenant_missing"})
        note_value = note.strip() if note else None
        record = QuickstartTrialExtensionRecord(
            tenant_slug=normalized_slug,
            extended_days=days,
            requested_by=actor,
            note=note_value,
        )
        created = await orm.admin.quickstart_trial_extensions.create(record)
        await self._chatops.notify(
            "trial_extended",
            f"Trial for tenant '{normalized_slug}' extended by {days} days",
            extra={
                "tenant": normalized_slug,
                "actor": actor,
                "days": days,
                "note": note_value,
            },
        )
        return cast(QuickstartTrialExtensionRecord, created)

    async def tenant_metrics(self, orm: ORM) -> dict[str, Any]:
        tenants = await orm.admin.quickstart_tenants.list(order_by=("slug",))
        trials = await orm.admin.quickstart_trial_extensions.list(order_by=("created_at",))
        tickets = await orm.admin.support_tickets.list(order_by=("created_at",))
        active_tenants = len(tenants)
        trial_extensions = len(trials)
        tickets_open = sum(1 for ticket in tickets if ticket.status != SupportTicketStatus.RESOLVED)
        tickets_resolved = sum(1 for ticket in tickets if ticket.status == SupportTicketStatus.RESOLVED)
        return {
            "tenants": active_tenants,
            "trial_extensions": trial_extensions,
            "support_tickets": {
                "open": tickets_open,
                "resolved": tickets_resolved,
                "total": len(tickets),
            },
        }

    async def system_diagnostics(self, orm: ORM) -> dict[str, Any]:
        tenants = await orm.admin.quickstart_tenants.list(order_by=("slug",))
        tickets = await orm.admin.support_tickets.list(order_by=("created_at",))
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenants": [tenant.slug for tenant in tenants],
            "chatops": {
                "enabled": self._chatops.settings.enabled,
                "configured": self._chatops.settings.webhook is not None,
                "admin_workspace": self._chatops.settings.admin_workspace,
            },
            "support": {
                "total": len(tickets),
                "open": sum(
                    1 for ticket in tickets if ticket.status != SupportTicketStatus.RESOLVED
                ),
            },
            "allowed_tenants": sorted(self._app.tenant_resolver.allowed_tenants),
        }

    async def create_support_ticket(
        self,
        tenant: TenantContext,
        payload: QuickstartSupportTicketRequest,
        *,
        orm: ORM,
        actor: str,
    ) -> QuickstartSupportTicketRecord:
        subject = payload.subject.strip()
        message = payload.message.strip()
        if not subject or not message:
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_ticket"})
        ticket_kind = SupportTicketKind(payload.kind)
        admin_record = QuickstartSupportTicketRecord(
            tenant_slug=tenant.tenant,
            kind=ticket_kind,
            subject=subject,
            message=message,
        )
        created = await orm.admin.support_tickets.create(admin_record)
        tenant_record = QuickstartTenantSupportTicketRecord(
            admin_ticket_id=created.id,
            kind=ticket_kind,
            subject=subject,
            message=message,
        )
        await orm.tenants.support_tickets.create(tenant=tenant, data=tenant_record)
        await self._chatops.notify(
            "support_ticket_created",
            f"Support ticket '{created.id}' opened by {tenant.tenant}",
            extra={
                "ticket_id": created.id,
                "tenant": tenant.tenant,
                "actor": actor,
                "kind": ticket_kind.value,
                "subject": subject,
            },
        )
        return created

    async def update_support_ticket(
        self,
        ticket_id: str,
        payload: QuickstartSupportTicketUpdateRequest,
        *,
        orm: ORM,
        actor: str,
    ) -> QuickstartSupportTicketRecord:
        record = await orm.admin.support_tickets.get(filters={"id": ticket_id})
        if record is None:
            raise HTTPError(Status.NOT_FOUND, {"detail": "ticket_missing"})
        status = SupportTicketStatus(payload.status)
        log_entries = list(record.updates)
        if payload.note:
            log_entries.append(
                QuickstartSupportTicketUpdateLog(
                    timestamp=datetime.now(timezone.utc),
                    actor=actor,
                    note=payload.note.strip(),
                )
            )
        updated = await orm.admin.support_tickets.update(
            filters={"id": ticket_id},
            values={
                "status": status,
                "updates": tuple(log_entries),
                "updated_by": actor,
            },
        )
        tenant_context = self._app.tenant_resolver.context_for(record.tenant_slug, TenantScope.TENANT)
        tenant_record = await orm.tenants.support_tickets.get(
            tenant=tenant_context,
            filters={"admin_ticket_id": ticket_id},
        )
        if tenant_record is not None:
            tenant_updates = list(tenant_record.updates)
            if payload.note:
                tenant_updates.append(
                    QuickstartSupportTicketUpdateLog(
                        timestamp=datetime.now(timezone.utc),
                        actor=actor,
                        note=payload.note.strip(),
                    )
                )
            await orm.tenants.support_tickets.update(
                tenant=tenant_context,
                filters={"admin_ticket_id": ticket_id},
                values={
                    "status": status,
                    "updates": tuple(tenant_updates),
                    "updated_by": actor,
                },
            )
        await self._chatops.notify(
            "support_ticket_updated",
            f"Support ticket '{ticket_id}' updated by {actor}",
            extra={
                "ticket_id": ticket_id,
                "status": status.value,
                "actor": actor,
                "note": payload.note,
            },
        )
        return cast(QuickstartSupportTicketRecord, updated)
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
    billing_path = f"{normalized}/admin/billing" if normalized else "/admin/billing"
    metrics_path = f"{normalized}/admin/metrics" if normalized else "/admin/metrics"
    diagnostics_path = (
        f"{normalized}/admin/diagnostics" if normalized else "/admin/diagnostics"
    )
    support_admin_path = (
        f"{normalized}/admin/support/tickets"
        if normalized
        else "/admin/support/tickets"
    )
    support_admin_ticket_path = (
        f"{support_admin_path}/{{ticket_id}}"
    )
    support_tenant_path = (
        f"{normalized}/support/tickets" if normalized else "/support/tickets"
    )
    tenants_path = f"{normalized}/tenants" if normalized else "/tenants"
    chatops_settings_path = (
        f"{normalized}/admin/chatops" if normalized else "/admin/chatops"
    )
    chatops_slash_path = f"{normalized}/chatops/slash" if normalized else "/chatops/slash"
    workspaces_path = f"{normalized}/workspaces" if normalized else "/workspaces"
    tiles_collection_path = f"{workspaces_path}/{{wsId}}/tiles"
    tile_item_path = f"{tiles_collection_path}/{{tileId}}"
    tile_permissions_path = f"{tile_item_path}/permissions"
    rbac_permission_sets_path = f"{workspaces_path}/{{wsId}}/rbac/permission-sets"
    rbac_role_assign_path = f"{workspaces_path}/{{wsId}}/rbac/roles/{{roleId}}/assign"
    delegations_path = f"{normalized}/delegations" if normalized else "/delegations"
    delegation_item_path = f"{delegations_path}/{{delegationId}}"
    audit_logs_path = f"{workspaces_path}/{{wsId}}/audit-logs"
    audit_logs_export_path = f"{audit_logs_path}/export"

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
        initial_chatops_config = app.chatops.config
        initial_chatops_settings = QuickstartChatOpsSettings(
            enabled=initial_chatops_config.enabled,
            webhook=(
                initial_chatops_config.default
                if initial_chatops_config.enabled
                else None
            ),
        )
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

        tile_domain = QuickstartTileService(orm)
        rbac_domain = QuickstartRbacService(orm)
        delegation_domain = QuickstartDelegationService(orm)
        audit_domain = QuickstartAuditService(orm)

        app.dependencies.provide(TileService, lambda: tile_domain)
        app.dependencies.provide(RbacService, lambda: rbac_domain)
        app.dependencies.provide(DelegationService, lambda: delegation_domain)
        app.dependencies.provide(AuditService, lambda: audit_domain)

        async def _cedar_engine_dependency(request: Request) -> CedarEngine:
            tenant_ctx = request.tenant
            if tenant_ctx.scope is TenantScope.TENANT:
                return await build_cedar_engine(orm, tenant=tenant_ctx)
            if tenant_ctx.scope is TenantScope.ADMIN:
                workspace_id = request.path_params.get("wsId")
                if workspace_id:
                    target = TenantContext(
                        tenant=workspace_id,
                        site=tenant_ctx.site,
                        domain=tenant_ctx.domain,
                        scope=TenantScope.TENANT,
                    )
                    try:
                        return await build_cedar_engine(orm, tenant=target)
                    except HTTPError:
                        return CedarEngine(())
            return CedarEngine(())

        app.dependencies.provide(CedarEngine, _cedar_engine_dependency)

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

        def _require_admin(request: Request) -> None:
            if request.tenant.scope is not TenantScope.ADMIN:
                raise HTTPError(Status.FORBIDDEN, {"detail": "admin_required"})

        def _normalize_slug(raw: str) -> str:
            return raw.strip().lower()

        chatops_control = QuickstartChatOpsControlPlane(
            app,
            initial_chatops_settings,
            command_pattern=_TENANT_SLUG_PATTERN,
        )
        chatops_control.configure(initial_chatops_settings)

        admin_control = QuickstartAdminControlPlane(
            app,
            slug_normalizer=_normalize_slug,
            slug_pattern=_TENANT_SLUG_PATTERN,
            ensure_contexts=_ensure_contexts_for,
            chatops=chatops_control,
            sync_allowed_tenants=_sync_allowed_tenants,
        )

        chatops_control.register_action_binding("create_tenant", "quickstart.chatops.create_tenant")
        chatops_control.register_action_binding("extend_trial", "quickstart.chatops.extend_trial")
        chatops_control.register_action_binding("tenant_metrics", "quickstart.chatops.tenant_metrics")
        chatops_control.register_action_binding(
            "system_diagnostics", "quickstart.chatops.system_diagnostics"
        )
        chatops_control.register_action_binding("ticket_update", "quickstart.chatops.ticket_update")

        @app.chatops_command(
            ChatOpsSlashCommand(
                name="create-tenant",
                description="Provision a new tenant from Slack.",
                visibility="admin",
                aliases=("quickstart-create-tenant",),
            ),
            name="quickstart.chatops.create_tenant",
        )
        async def quickstart_chatops_create_tenant_command(
            context: ChatOpsCommandContext,
        ) -> dict[str, Any]:
            slug_arg = context.args.get("slug")
            name_arg = context.args.get("name")
            if not slug_arg or not name_arg:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "missing_arguments"})
            orm = await context.dependencies.get(ORM)
            engine = await context.dependencies.get(QuickstartAuthEngine)
            record = await admin_control.create_tenant_from_inputs(
                slug_arg,
                name_arg,
                orm=orm,
                engine=engine,
                actor=context.actor,
                source="chatops",
            )
            return {
                "status": "ok",
                "action": "create_tenant",
                "tenant": to_builtins(record),
            }

        @app.chatops_command(
            ChatOpsSlashCommand(
                name="extend-trial",
                description="Extend a tenant's trial period from Slack.",
                visibility="admin",
                aliases=("quickstart-extend-trial",),
            ),
            name="quickstart.chatops.extend_trial",
        )
        async def quickstart_chatops_extend_trial_command(
            context: ChatOpsCommandContext,
        ) -> dict[str, Any]:
            tenant_arg = context.args.get("tenant")
            days_arg = context.args.get("days")
            if not tenant_arg or not days_arg:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "missing_arguments"})
            try:
                days = int(days_arg)
            except ValueError as exc:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_days"}) from exc
            note_arg = context.args.get("note")
            orm = await context.dependencies.get(ORM)
            extension = await admin_control.grant_trial_extension(
                tenant_arg,
                days,
                note=note_arg,
                actor=context.actor,
                orm=orm,
            )
            return {
                "status": "ok",
                "action": "extend_trial",
                "extension": to_builtins(extension),
            }

        @app.chatops_command(
            ChatOpsSlashCommand(
                name="tenant-metrics",
                description="Summarize tenant metrics for administrators.",
                visibility="admin",
                aliases=("quickstart-tenant-metrics",),
            ),
            name="quickstart.chatops.tenant_metrics",
        )
        async def quickstart_chatops_tenant_metrics_command(
            context: ChatOpsCommandContext,
        ) -> dict[str, Any]:
            orm = await context.dependencies.get(ORM)
            metrics = await admin_control.tenant_metrics(orm)
            return {
                "status": "ok",
                "action": "tenant_metrics",
                "metrics": metrics,
            }

        @app.chatops_command(
            ChatOpsSlashCommand(
                name="system-diagnostics",
                description="Display quickstart diagnostics and health checks.",
                visibility="admin",
                aliases=("quickstart-system-diagnostics",),
            ),
            name="quickstart.chatops.system_diagnostics",
        )
        async def quickstart_chatops_system_diagnostics_command(
            context: ChatOpsCommandContext,
        ) -> dict[str, Any]:
            orm = await context.dependencies.get(ORM)
            diagnostics = await admin_control.system_diagnostics(orm)
            return {
                "status": "ok",
                "action": "system_diagnostics",
                "diagnostics": diagnostics,
            }

        @app.chatops_command(
            ChatOpsSlashCommand(
                name="ticket-update",
                description="Post an update to a customer support ticket.",
                visibility="admin",
                aliases=("quickstart-ticket-update",),
            ),
            name="quickstart.chatops.ticket_update",
        )
        async def quickstart_chatops_ticket_update_command(
            context: ChatOpsCommandContext,
        ) -> dict[str, Any]:
            ticket_id = context.args.get("ticket")
            status_arg = context.args.get("status")
            if not ticket_id or not status_arg:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "missing_arguments"})
            if status_arg not in {"open", "responded", "resolved"}:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_status"})
            update_payload = QuickstartSupportTicketUpdateRequest(
                status=status_arg, note=context.args.get("note")
            )
            orm = await context.dependencies.get(ORM)
            ticket = await admin_control.update_support_ticket(
                ticket_id,
                update_payload,
                orm=orm,
                actor=context.actor,
            )
            return {
                "status": "ok",
                "action": "ticket_update",
                "ticket": to_builtins(ticket),
            }


        @app.post(tiles_collection_path, name="quickstart_tiles_create")
        async def quickstart_tiles_create(
            request: Request,
            wsId: str,
            payload: TileCreate,
            service: TileService,
        ) -> Response:
            result = await service.create_tile(
                tenant=request.tenant,
                workspace_id=wsId,
                principal=request.principal,
                payload=payload,
            )
            return JSONResponse(to_builtins(result), status=int(Status.CREATED))

        @app.route(tile_item_path, methods=("PATCH",), name="quickstart_tiles_update")
        async def quickstart_tiles_update(
            request: Request,
            wsId: str,
            tileId: str,
            payload: TileUpdate,
            service: TileService,
        ) -> Response:
            result = await service.update_tile(
                tenant=request.tenant,
                workspace_id=wsId,
                tile_id=tileId,
                principal=request.principal,
                payload=payload,
            )
            return JSONResponse(to_builtins(result))

        @app.route(tile_item_path, methods=("DELETE",), name="quickstart_tiles_delete")
        async def quickstart_tiles_delete(
            request: Request,
            wsId: str,
            tileId: str,
            service: TileService,
        ) -> Response:
            await service.delete_tile(
                tenant=request.tenant,
                workspace_id=wsId,
                tile_id=tileId,
                principal=request.principal,
            )
            return Response(status=int(Status.NO_CONTENT))

        @app.route(
            tile_permissions_path,
            methods=("PUT",),
            name="quickstart_tiles_permissions",
        )
        async def quickstart_tiles_permissions(
            request: Request,
            wsId: str,
            tileId: str,
            payload: TilePermissions,
            service: TileService,
        ) -> Response:
            result = await service.set_permissions(
                tenant=request.tenant,
                workspace_id=wsId,
                tile_id=tileId,
                principal=request.principal,
                permissions=payload,
            )
            return JSONResponse(to_builtins(result))

        @app.post(
            rbac_permission_sets_path,
            name="quickstart_rbac_permission_sets_create",
        )
        async def quickstart_rbac_permission_sets_create(
            request: Request,
            wsId: str,
            payload: PermissionSetCreate,
            service: RbacService,
        ) -> Response:
            _require_admin(request)
            result = await service.create_permission_set(
                tenant=request.tenant,
                workspace_id=wsId,
                principal=request.principal,
                payload=payload,
            )
            return JSONResponse(to_builtins(result), status=int(Status.CREATED))

        @app.post(rbac_role_assign_path, name="quickstart_rbac_assign_role")
        async def quickstart_rbac_assign_role(
            request: Request,
            wsId: str,
            roleId: str,
            payload: RoleAssignment,
            service: RbacService,
        ) -> Response:
            _require_admin(request)
            result = await service.assign_role(
                tenant=request.tenant,
                workspace_id=wsId,
                role_id=roleId,
                principal=request.principal,
                payload=payload,
            )
            return JSONResponse(to_builtins(result))

        @app.post(delegations_path, name="quickstart_delegations_grant")
        async def quickstart_delegations_grant(
            request: Request,
            payload: DelegationGrant,
            service: DelegationService,
        ) -> Response:
            if request.tenant.scope is not TenantScope.TENANT:
                raise HTTPError(Status.FORBIDDEN, {"detail": "tenant_required"})
            delegation = await service.grant(
                tenant=request.tenant,
                principal=request.principal,
                payload=payload,
            )
            return JSONResponse(to_builtins(delegation), status=int(Status.CREATED))

        @app.route(
            delegation_item_path,
            methods=("DELETE",),
            name="quickstart_delegations_revoke",
        )
        async def quickstart_delegations_revoke(
            request: Request,
            delegationId: str,
            service: DelegationService,
        ) -> Response:
            if request.tenant.scope is not TenantScope.TENANT:
                raise HTTPError(Status.FORBIDDEN, {"detail": "tenant_required"})
            await service.revoke(
                tenant=request.tenant,
                principal=request.principal,
                delegation_id=delegationId,
            )
            return Response(status=int(Status.NO_CONTENT))

        @app.get(audit_logs_path, name="quickstart_audit_logs")
        async def quickstart_audit_logs(
            request: Request,
            wsId: str,
            service: AuditService,
        ) -> Response:
            _require_admin(request)
            query = request.query(QuickstartAuditLogQuery)
            page = await service.read(
                tenant=request.tenant,
                workspace_id=wsId,
                principal=request.principal,
                actor=query.actor,
                action=query.action,
                entity=query.entity,
                from_time=query.from_time,
                to_time=query.to_time,
            )
            return JSONResponse(to_builtins(page))

        @app.get(audit_logs_export_path, name="quickstart_audit_logs_export")
        async def quickstart_audit_logs_export(
            request: Request,
            wsId: str,
            service: AuditService,
        ) -> Response:
            _require_admin(request)
            query = request.query(QuickstartAuditLogQuery)
            export = await service.export(
                tenant=request.tenant,
                workspace_id=wsId,
                principal=request.principal,
                query=AuditLogExportQuery(format=query.format or "json"),
                actor=query.actor,
                action=query.action,
                entity=query.entity,
                from_time=query.from_time,
                to_time=query.to_time,
            )
            headers: list[tuple[str, str]] = [("content-type", export.content_type)]
            if export.filename:
                headers.append(
                    (
                        "content-disposition",
                        f'attachment; filename="{export.filename}"',
                    )
                )
            return Response(status=int(Status.OK), headers=tuple(headers), body=export.body)


        @app.get(billing_path, name="quickstart_admin_billing")
        async def quickstart_admin_billing(request: Request, orm: ORM) -> Response:
            _require_admin(request)
            records = await orm.admin.billing.list(order_by=("created_at desc",))
            return JSONResponse(tuple(to_builtins(record) for record in records))

        @app.post(billing_path, name="quickstart_admin_create_billing")
        async def quickstart_admin_create_billing(
            request: Request,
            payload: BillingCreateRequest,
            orm: ORM,
        ) -> Response:
            _require_admin(request)
            record = await orm.admin.billing.create(to_builtins(payload))
            record_payload = to_builtins(record)
            status_value = BillingStatus(record_payload.get("status", record.status))
            await chatops_control.notify(
                "billing_updated",
                f"Billing updated for {record.customer_id} ({status_value.value})",
                extra={
                    "event": "billing_updated",
                    **record_payload,
                },
            )
            if status_value == BillingStatus.PAST_DUE:
                await chatops_control.notify(
                    "subscription_past_due",
                    f"Subscription for {record.customer_id} is past due",
                    extra={
                        "event": "subscription_past_due",
                        **record_payload,
                    },
                )
            return JSONResponse(record_payload, status=201)

        @app.get(metrics_path, name="quickstart_admin_metrics")
        async def quickstart_admin_metrics(request: Request, orm: ORM) -> Response:
            _require_admin(request)
            metrics = await admin_control.tenant_metrics(orm)
            return JSONResponse(metrics)

        @app.get(diagnostics_path, name="quickstart_admin_diagnostics")
        async def quickstart_admin_diagnostics(request: Request, orm: ORM) -> Response:
            _require_admin(request)
            diagnostics = await admin_control.system_diagnostics(orm)
            return JSONResponse(diagnostics)

        @app.get(support_admin_path, name="quickstart_admin_support_tickets")
        async def quickstart_admin_support_tickets(request: Request, orm: ORM) -> Response:
            _require_admin(request)
            tickets = await orm.admin.support_tickets.list(order_by=("created_at desc",))
            return JSONResponse(tuple(to_builtins(ticket) for ticket in tickets))

        @app.post(
            support_admin_ticket_path,
            name="quickstart_admin_support_ticket_update",
        )
        async def quickstart_admin_support_ticket_update(
            request: Request,
            ticket_id: str,
            payload: QuickstartSupportTicketUpdateRequest,
            orm: ORM,
        ) -> Response:
            _require_admin(request)
            updated = await admin_control.update_support_ticket(
                ticket_id,
                payload,
                orm=orm,
                actor=request.headers.get("x-artemis-actor", "quickstart-admin"),
            )
            return JSONResponse(to_builtins(updated))

        @app.get(support_tenant_path, name="quickstart_tenant_support_tickets")
        async def quickstart_tenant_support_tickets(request: Request, orm: ORM) -> Response:
            if request.tenant.scope is TenantScope.ADMIN:
                return JSONResponse(())
            tickets = await orm.tenants.support_tickets.list(
                tenant=request.tenant,
                order_by=("created_at desc",),
            )
            return JSONResponse(tuple(to_builtins(ticket) for ticket in tickets))

        @app.post(support_tenant_path, name="quickstart_tenant_create_support_ticket")
        async def quickstart_tenant_create_support_ticket(
            request: Request,
            payload: QuickstartSupportTicketRequest,
            orm: ORM,
        ) -> Response:
            if request.tenant.scope is not TenantScope.TENANT:
                raise HTTPError(Status.FORBIDDEN, {"detail": "tenant_required"})
            actor = request.headers.get("x-artemis-actor", request.tenant.tenant)
            ticket = await admin_control.create_support_ticket(
                request.tenant,
                payload,
                orm=orm,
                actor=actor,
            )
            return JSONResponse(to_builtins(ticket), status=201)

        @app.get(tenants_path, name="quickstart_tenants")
        async def quickstart_list_tenants(request: Request, orm: ORM) -> Response:
            if request.tenant.scope is TenantScope.ADMIN:
                records = await orm.admin.quickstart_tenants.list(order_by=("slug",))
            else:
                record = await orm.admin.quickstart_tenants.get(
                    filters={"slug": request.tenant.tenant}
                )
                records = [] if record is None else [record]
            return JSONResponse(tuple(to_builtins(record) for record in records))

        @app.post(tenants_path, name="quickstart_create_tenant")
        async def quickstart_create_tenant(
            request: Request,
            payload: QuickstartTenantCreateRequest,
            orm: ORM,
            engine: QuickstartAuthEngine,
        ) -> Response:
            _require_admin(request)
            actor = request.headers.get("x-artemis-actor", "quickstart-admin")
            record = await admin_control.create_tenant_from_inputs(
                payload.slug,
                payload.name,
                orm=orm,
                engine=engine,
                actor=actor,
                source="api",
            )
            return JSONResponse(to_builtins(record), status=201)

        @app.get(chatops_settings_path, name="quickstart_admin_chatops_settings")
        async def quickstart_admin_chatops_settings(
            request: Request,
        ) -> Response:
            _require_admin(request)
            settings = chatops_control.serialize_settings()
            return JSONResponse(settings)

        @app.post(chatops_settings_path, name="quickstart_admin_update_chatops_settings")
        async def quickstart_update_chatops_settings(
            request: Request,
            payload: QuickstartChatOpsSettings,
        ) -> Response:
            _require_admin(request)
            if payload.enabled and payload.webhook is None:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "webhook_required"})
            commands_iterable = payload.slash_commands or _default_slash_commands()
            normalized_commands = chatops_control.normalize_commands(commands_iterable)
            settings = QuickstartChatOpsSettings(
                enabled=payload.enabled,
                webhook=payload.webhook,
                notifications=payload.notifications,
                slash_commands=normalized_commands,
                bot_user_id=payload.bot_user_id,
                admin_workspace=payload.admin_workspace,
            )
            chatops_control.configure(settings)
            return JSONResponse(chatops_control.serialize_settings())

        @app.post(chatops_slash_path, name="quickstart_chatops_slash")
        async def quickstart_chatops_slash(
            request: Request,
            payload: QuickstartSlashCommandInvocation,
        ) -> Response:
            settings = chatops_control.settings
            if not settings.enabled or settings.webhook is None:
                detail = "chatops_disabled" if not settings.enabled else "chatops_unconfigured"
                raise HTTPError(Status.FORBIDDEN, {"detail": detail})
            try:
                binding, args, actor = chatops_control.resolve_invocation(request, payload)
            except ChatOpsInvocationError as exc:
                detail = {"detail": exc.code}
                status = Status.BAD_REQUEST
                if exc.code == "invalid_bot_mention":
                    status = Status.FORBIDDEN
                raise HTTPError(status, detail) from exc
            except ChatOpsCommandResolutionError as exc:
                detail = {"detail": exc.code}
                if exc.code == "unknown_command":
                    raise HTTPError(Status.NOT_FOUND, detail) from exc
                raise HTTPError(Status.FORBIDDEN, detail) from exc
            scope = app.dependencies.scope(request)
            context = ChatOpsCommandContext(
                request=request,
                payload=payload,
                args=args,
                actor=actor,
                dependencies=scope,
            )
            result = await binding.handler(context)
            if isinstance(result, Response):
                return result
            return JSONResponse(result)

    providers = getattr(app.dependencies, "_providers", {})

    def _missing_dependency_factory(dependency: type[Any]) -> Callable[[], Any]:
        def _missing_dependency() -> Any:  # pragma: no cover - defensive wiring path
            raise HTTPError(
                Status.NOT_IMPLEMENTED,
                {
                    "detail": "dependency_unavailable",
                    "dependency": dependency.__name__,
                },
            )

        return _missing_dependency

    for dependency in (TileService, RbacService, DelegationService, AuditService):
        if dependency not in providers:
            app.dependencies.provide(dependency, _missing_dependency_factory(dependency))

    if CedarEngine not in providers:
        app.dependencies.provide(CedarEngine, lambda: CedarEngine(()))

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
    "BillingCreateRequest",
    "LoginStep",
    "MfaAttempt",
    "PasskeyAttempt",
    "PasswordAttempt",
    "QuickstartAdminControlPlane",
    "QuickstartAdminRealm",
    "QuickstartAdminUserRecord",
    "QuickstartAuthConfig",
    "QuickstartAuthEngine",
    "QuickstartChatOpsControlPlane",
    "QuickstartChatOpsNotificationChannels",
    "QuickstartChatOpsSettings",
    "QuickstartLoginResponse",
    "QuickstartPasskey",
    "QuickstartPasskeyRecord",
    "QuickstartRepository",
    "QuickstartSeedStateRecord",
    "QuickstartSeeder",
    "QuickstartSession",
    "QuickstartSlashCommand",
    "QuickstartSlashCommandInvocation",
    "QuickstartSsoProvider",
    "QuickstartSupportTicketRecord",
    "QuickstartSupportTicketRequest",
    "QuickstartSupportTicketUpdateLog",
    "QuickstartSupportTicketUpdateRequest",
    "QuickstartTenant",
    "QuickstartTenantCreateRequest",
    "QuickstartTenantRecord",
    "QuickstartTenantSupportTicketRecord",
    "QuickstartTenantUserRecord",
    "QuickstartTrialExtensionRecord",
    "QuickstartUser",
    "attach_quickstart",
    "ensure_tenant_schemas",
    "load_quickstart_auth_from_env",
    "quickstart_migrations",
]
