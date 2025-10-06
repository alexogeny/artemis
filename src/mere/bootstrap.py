"""Developer bootstrap routes for OpenAPI, authentication, and tenancy scaffolding."""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone
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
from cryptography.fernet import Fernet, InvalidToken
from msgspec import Struct, convert, field, json, to_builtins

from .application import MereApp
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
from .database import Database, SecretResolver, SecretValue, _quote_identifier
from .domain.bootstrap_services import (
    BootstrapAuditService,
    BootstrapDelegationService,
    BootstrapRbacService,
    BootstrapTileService,
    build_cedar_engine,
)
from .domain.services import (
    AuditLogExportQuery,
    AuditService,
    DelegationGrant,
    DelegationRecord,
    DelegationService,
    PermissionSetCreate,
    PermissionSetRecord,
    RbacService,
    RoleAssignment,
    TileCreate,
    TilePermissions,
    TileRecord,
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


_TENANT_SLUG_PATTERN: Final[RureRegex] = cast("RureRegex", rure.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"))


class BootstrapSsoProvider(Struct, frozen=True):
    """Metadata describing a federated identity provider."""

    slug: str
    kind: str
    display_name: str
    redirect_url: str


class BootstrapPasskey(Struct, frozen=True):
    """Passkey configuration for the bootstrap."""

    credential_id: str
    secret_ciphertext: SecretValue
    label: str | None = None


class BootstrapPasskeyCipher:
    """Encrypt and decrypt bootstrap passkey material."""

    def __init__(self, *, key_material: bytes) -> None:
        if not key_material:
            raise ValueError("Bootstrap passkey cipher requires non-empty key material")
        digest = hashlib.sha256(key_material).digest()
        fernet_key = base64.urlsafe_b64encode(digest)
        self._fernet = Fernet(fernet_key)

    @classmethod
    def from_secret(cls, secret: str | bytes) -> "BootstrapPasskeyCipher":
        material = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        return cls(key_material=material)

    def encrypt(self, secret: bytes) -> str:
        """Encrypt ``secret`` returning a UTF-8 ciphertext."""

        return self._fernet.encrypt(secret).decode("utf-8")

    def decrypt(self, ciphertext: str) -> bytearray:
        """Decrypt ``ciphertext`` returning a mutable buffer for wiping."""

        try:
            plaintext = self._fernet.decrypt(ciphertext.encode("utf-8"))
        except InvalidToken as exc:  # pragma: no cover - defensive guard
            raise RuntimeError("Invalid bootstrap passkey ciphertext") from exc
        return bytearray(plaintext)


class BootstrapUser(Struct, frozen=True):
    """Bootstrap user profile with authentication factors."""

    id: str
    email: str
    password: str | None = None
    passkeys: tuple[BootstrapPasskey, ...] = ()
    mfa_code: str | None = None
    sso: BootstrapSsoProvider | None = None


class BootstrapTenant(Struct, frozen=True):
    """Tenant definition used by the bootstrap."""

    slug: str
    name: str
    users: tuple[BootstrapUser, ...]


class BootstrapAdminRealm(Struct, frozen=True):
    """Administrative realm definition for the bootstrap."""

    users: tuple[BootstrapUser, ...]


class BootstrapChatOpsNotificationChannels(Struct, frozen=True):
    """Channel overrides for ChatOps notifications."""

    tenant_created: str | None = None
    billing_updated: str | None = None
    subscription_past_due: str | None = None
    trial_extended: str | None = None
    support_ticket_created: str | None = None
    support_ticket_updated: str | None = None


class BootstrapSlashCommand(Struct, frozen=True):
    """ChatOps command metadata for the bootstrap surface."""

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


class BootstrapKanbanCard(Struct, frozen=True, omit_defaults=True):
    """Card rendered within the workspace kanban board."""

    id: str
    title: str
    status: Literal["backlog", "in_progress", "done"]
    created_at: datetime = field(name="createdAt")
    updated_at: datetime = field(name="updatedAt")
    assignee: str | None = None
    tags: tuple[str, ...] = ()
    summary: str | None = None
    severity: Literal["low", "medium", "high"] = "low"


class BootstrapKanbanColumn(Struct, frozen=True, omit_defaults=True):
    """Column on the kanban board with associated cards."""

    key: Literal["backlog", "in_progress", "done"]
    title: str
    cards: tuple[BootstrapKanbanCard, ...]


class BootstrapKanbanBoard(Struct, frozen=True, omit_defaults=True):
    """Workspace kanban board summarizing support efforts."""

    workspace_id: str = field(name="workspaceId")
    columns: tuple[BootstrapKanbanColumn, ...]
    updated_at: datetime = field(name="updatedAt")


class BootstrapWorkspaceSettings(Struct, frozen=True, omit_defaults=True):
    """Workspace configuration payload returned to the UI."""

    workspace_id: str = field(name="workspaceId")
    name: str
    timezone: str
    currency: str
    features: tuple[str, ...]
    tile_count: int = field(name="tileCount")
    ai_insights_enabled: bool = field(name="aiInsightsEnabled")
    alerts: tuple[str, ...] = ()


class BootstrapNotification(Struct, frozen=True, omit_defaults=True):
    """Notification entry surfaced to workspace operators."""

    id: str
    workspace_id: str = field(name="workspaceId")
    kind: Literal["system", "support", "billing", "trial"]
    title: str
    message: str
    occurred_at: datetime = field(name="occurredAt")
    actor: str | None = None
    severity: Literal["info", "warning", "critical"] = "info"
    metadata: Mapping[str, Any] = field(default_factory=dict)


def _default_slash_commands() -> tuple[BootstrapSlashCommand, ...]:
    return (
        BootstrapSlashCommand(
            name="create-tenant",
            action="create_tenant",
            description="Provision a new tenant from Slack.",
            aliases=("bootstrap-create-tenant",),
        ),
        BootstrapSlashCommand(
            name="extend-trial",
            action="extend_trial",
            description="Extend a tenant's trial period from Slack.",
            aliases=("bootstrap-extend-trial",),
        ),
        BootstrapSlashCommand(
            name="tenant-metrics",
            action="tenant_metrics",
            description="Summarize tenant metrics for administrators.",
            aliases=("bootstrap-tenant-metrics",),
        ),
        BootstrapSlashCommand(
            name="system-diagnostics",
            action="system_diagnostics",
            description="Display bootstrap diagnostics and health checks.",
            aliases=("bootstrap-system-diagnostics",),
        ),
        BootstrapSlashCommand(
            name="ticket-update",
            action="ticket_update",
            description="Post an update to a customer support ticket.",
            aliases=("bootstrap-ticket-update",),
        ),
    )


_KANBAN_COLUMN_TITLES: Mapping[str, str] = {
    "backlog": "Backlog",
    "in_progress": "In Progress",
    "done": "Done",
}

_KANBAN_STATUS_BY_TICKET: Mapping[SupportTicketStatus, str] = {
    SupportTicketStatus.OPEN: "backlog",
    SupportTicketStatus.RESPONDED: "in_progress",
    SupportTicketStatus.RESOLVED: "done",
}

_KANBAN_SEVERITY_BY_KIND: Mapping[SupportTicketKind, str] = {
    SupportTicketKind.GENERAL: "low",
    SupportTicketKind.FEEDBACK: "medium",
    SupportTicketKind.ISSUE: "high",
}

_SAMPLE_FEED_BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _register_response_model(
    handler: Callable[..., Any],
    *,
    status: int,
    model: Any | None,
    description: str = "Success",
    media_type: str = "application/json",
) -> None:
    """Attach response metadata to ``handler`` for OpenAPI generation."""

    existing = getattr(handler, "__mere_response_models__", {})
    updated = dict(existing)
    updated[int(status)] = {
        "model": model,
        "description": description,
        "media_type": media_type,
    }
    setattr(handler, "__mere_response_models__", updated)


def _sample_notification_feed(workspace_id: str) -> tuple[BootstrapNotification, ...]:
    """Return a canned notification feed for empty workspaces."""

    base = _SAMPLE_FEED_BASE
    return (
        BootstrapNotification(
            id=f"{workspace_id}-welcome",
            workspace_id=workspace_id,
            kind="system",
            title="Workspace provisioned",
            message=f"Workspace {workspace_id} is ready to go.",
            occurred_at=base,
            severity="info",
            metadata={"workspace": workspace_id},
        ),
        BootstrapNotification(
            id=f"{workspace_id}-first-ticket",
            workspace_id=workspace_id,
            kind="support",
            title="Track customer feedback",
            message="Create your first support ticket to populate the kanban board.",
            occurred_at=base + timedelta(hours=1),
            severity="info",
        ),
        BootstrapNotification(
            id=f"{workspace_id}-billing-setup",
            workspace_id=workspace_id,
            kind="billing",
            title="Connect billing",
            message="Add a billing record to unlock usage reporting.",
            occurred_at=base + timedelta(hours=2),
            severity="warning",
        ),
    )


def _sample_kanban_board(workspace_id: str) -> BootstrapKanbanBoard:
    """Build a predictable kanban board when no data exists."""

    base = _SAMPLE_FEED_BASE
    cards = {
        "backlog": (
            BootstrapKanbanCard(
                id=f"{workspace_id}-kb-1",
                title="Gather product requirements",
                status="backlog",
                created_at=base,
                updated_at=base,
                tags=("research",),
                summary="Capture the top customer requests for the next release.",
            ),
        ),
        "in_progress": (
            BootstrapKanbanCard(
                id=f"{workspace_id}-kb-2",
                title="Triage onboarding ticket",
                status="in_progress",
                created_at=base + timedelta(hours=1),
                updated_at=base + timedelta(hours=4),
                assignee="ops@demo.test",
                tags=("support",),
                summary="Customer reported slow workspace provisioning.",
                severity="medium",
            ),
        ),
        "done": (
            BootstrapKanbanCard(
                id=f"{workspace_id}-kb-3",
                title="Resolve billing anomaly",
                status="done",
                created_at=base + timedelta(hours=2),
                updated_at=base + timedelta(hours=6),
                tags=("billing",),
                summary="Investigated duplicate invoice and issued refund.",
                severity="high",
            ),
        ),
    }
    columns = tuple(
        BootstrapKanbanColumn(
            key=key,
            title=_KANBAN_COLUMN_TITLES[key],
            cards=cards[key],
        )
        for key in ("backlog", "in_progress", "done")
    )
    latest = max(card.updated_at for column in columns for card in column.cards)
    return BootstrapKanbanBoard(workspace_id=workspace_id, columns=columns, updated_at=latest)


class BootstrapChatOpsSettings(Struct, frozen=True):
    """Runtime ChatOps configuration maintained by the bootstrap routes."""

    enabled: bool = False
    webhook: SlackWebhookConfig | None = None
    notifications: BootstrapChatOpsNotificationChannels = field(default_factory=BootstrapChatOpsNotificationChannels)
    slash_commands: tuple[BootstrapSlashCommand, ...] = field(default_factory=_default_slash_commands)
    bot_user_id: str | None = None
    admin_workspace: str | None = None


class BootstrapAuditLogQuery(Struct, frozen=True, omit_defaults=True):
    """Query parameters used by audit log routes."""

    actor: str | None = None
    action: str | None = None
    entity: str | None = None
    from_time: datetime | None = field(name="from", default=None)
    to_time: datetime | None = field(name="to", default=None)
    format: Literal["csv", "json"] | None = None


class BootstrapSlashCommandInvocation(Struct, frozen=True):
    """Payload delivered from ChatOps slash command integrations."""

    text: str
    user_id: str
    command: str | None = None
    user_name: str | None = None
    channel_id: str | None = None
    workspace_id: str | None = None


BootstrapSession = AuthenticationFlowSession
BootstrapLoginResponse = AuthenticationFlowResponse


class BootstrapPasskeyRecord(Struct, frozen=True):
    """Database representation of a bootstrap passkey."""

    credential_id: str
    secret_ciphertext: str | None = None
    label: str | None = None
    _legacy_secret: str | None = field(default=None, name="secret")

    def resolved_secret_ciphertext(self) -> str:
        """Return the ciphertext, accepting legacy ``secret`` fields."""

        if self.secret_ciphertext:
            return self.secret_ciphertext
        if self._legacy_secret:
            return self._legacy_secret
        raise RuntimeError("Bootstrap passkey record missing ciphertext")


@model(scope=ModelScope.ADMIN, table="bootstrap_tenants")
class BootstrapTenantRecord(DatabaseModel):
    """Tenant metadata stored in the admin schema for the bootstrap."""

    slug: str
    name: str


@model(scope=ModelScope.ADMIN, table="bootstrap_admin_users")
class BootstrapAdminUserRecord(DatabaseModel):
    """Administrative login records for the bootstrap."""

    email: str
    password: str | None = None
    passkeys: tuple[BootstrapPasskeyRecord, ...] = field(default_factory=tuple)
    mfa_code: str | None = None


@model(scope=ModelScope.ADMIN, table="bootstrap_seed_state")
class BootstrapSeedStateRecord(DatabaseModel):
    """Tracks the last applied bootstrap seed fingerprint."""

    key: str
    fingerprint: str


@model(scope=ModelScope.TENANT, table="bootstrap_users")
class BootstrapTenantUserRecord(DatabaseModel):
    """Tenant-scoped login records for the bootstrap."""

    email: str
    password: str | None = None
    passkeys: tuple[BootstrapPasskeyRecord, ...] = field(default_factory=tuple)
    mfa_code: str | None = None
    sso_provider: BootstrapSsoProvider | None = None


@model(scope=ModelScope.ADMIN, table="bootstrap_trial_extensions")
class BootstrapTrialExtensionRecord(DatabaseModel):
    """Audit record describing ChatOps-driven trial extensions."""

    tenant_slug: str
    extended_days: int
    requested_by: str
    note: str | None = None


BootstrapSupportTicketUpdateLog = SupportTicketUpdate
BootstrapSupportTicketRecord = SupportTicket
BootstrapTenantSupportTicketRecord = TenantSupportTicket


class BootstrapAuthConfig(Struct, frozen=True):
    """Configuration for the bootstrap authentication engine."""

    tenants: tuple[BootstrapTenant, ...]
    admin: BootstrapAdminRealm
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
    """Payload for creating a billing record via the bootstrap routes."""

    customer_id: str
    plan_code: str
    status: BillingStatus
    amount_due_cents: int
    currency: str
    cycle_start: datetime
    cycle_end: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


class BootstrapTenantCreateRequest(Struct, frozen=True):
    """Payload for creating a tenant through the bootstrap API."""

    slug: str
    name: str


class BootstrapSupportTicketRequest(Struct, frozen=True):
    """Tenant-facing payload for creating a support ticket."""

    subject: str
    message: str
    kind: Literal["general", "feedback", "issue"]


class BootstrapSupportTicketUpdateRequest(Struct, frozen=True):
    """Administrative payload for updating a support ticket."""

    status: Literal["open", "responded", "resolved"]
    note: str | None = None


def bootstrap_migrations() -> tuple[Migration, ...]:
    """Return the migrations required to persist bootstrap data."""

    return (
        Migration(
            name="bootstrap_admin_tables",
            scope=MigrationScope.ADMIN,
            operations=(
                create_table_for_model(AdminAuditLogEntry),
                create_table_for_model(BillingRecord),
                create_table_for_model(BootstrapTenantRecord),
                create_table_for_model(BootstrapAdminUserRecord),
                create_table_for_model(BootstrapSeedStateRecord),
                create_table_for_model(BootstrapTrialExtensionRecord),
                create_table_for_model(Role),
                create_table_for_model(Permission),
                create_table_for_model(AdminRoleAssignment),
                create_table_for_model(SupportTicket),
            ),
        ),
        Migration(
            name="bootstrap_tenant_tables",
            scope=MigrationScope.TENANT,
            operations=(
                create_table_for_model(BootstrapTenantUserRecord),
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
    """Create tenant schemas for the bootstrap if they do not already exist."""

    schemas = {database.config.schema_for_tenant(tenant) for tenant in tenants}
    async with database.connection(schema=database.config.admin_schema) as connection:
        for schema in sorted(schemas):
            await connection.execute(f"CREATE SCHEMA IF NOT EXISTS {_quote_identifier(schema)}")


class BootstrapSeeder:
    """Populate the database with bootstrap identities."""

    _STATE_KEY: Final[str] = "bootstrap_auth"

    def __init__(
        self,
        orm: ORM,
        *,
        clock: Callable[[], datetime] | None = None,
        secret_resolver: SecretResolver | None = None,
    ) -> None:
        self._orm = orm
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._secret_resolver = secret_resolver

    async def apply(
        self,
        config: BootstrapAuthConfig,
        *,
        tenants: Mapping[str, TenantContext],
    ) -> bool:
        fingerprint = self._fingerprint(config)
        state_manager = self._orm.admin.bootstrap_seed_state
        existing_state = await state_manager.get(filters={"key": self._STATE_KEY})
        if existing_state and existing_state.fingerprint == fingerprint:
            return False

        admin_manager = self._orm.admin.bootstrap_admin_users
        await admin_manager.delete(filters=None)
        for user in config.admin.users:
            await admin_manager.create(
                BootstrapAdminUserRecord(
                    id=user.id,
                    email=user.email,
                    password=user.password,
                    passkeys=self._passkeys_to_records(user.passkeys),
                    mfa_code=user.mfa_code,
                )
            )

        tenant_manager = self._orm.admin.bootstrap_tenants
        await tenant_manager.delete(filters=None)
        for tenant in config.tenants:
            await tenant_manager.create(BootstrapTenantRecord(slug=tenant.slug, name=tenant.name))
            context = tenants.get(tenant.slug)
            if context is None:
                raise RuntimeError(f"Tenant '{tenant.slug}' is missing from the bootstrap tenant mapping")
            user_manager = self._orm.tenants.bootstrap_users
            await user_manager.delete(tenant=context, filters=None)
            for user in tenant.users:
                await user_manager.create(
                    BootstrapTenantUserRecord(
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
        existing_state: BootstrapSeedStateRecord | None,
        fingerprint: str,
    ) -> None:
        now = self._clock()
        if existing_state is None:
            await state_manager.create(
                BootstrapSeedStateRecord(
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

    def _passkeys_to_records(self, passkeys: tuple[BootstrapPasskey, ...]) -> tuple[BootstrapPasskeyRecord, ...]:
        if not passkeys:
            return ()
        records: list[BootstrapPasskeyRecord] = []
        for item in passkeys:
            ciphertext = item.secret_ciphertext.resolve(
                self._secret_resolver,
                field="bootstrap.passkeys.secret_ciphertext",
            )
            if ciphertext is None:
                raise RuntimeError("Bootstrap passkey ciphertext could not be resolved")
            records.append(
                BootstrapPasskeyRecord(
                    credential_id=item.credential_id,
                    secret_ciphertext=ciphertext,
                    label=item.label,
                )
            )
        return tuple(records)

    @staticmethod
    def _fingerprint(config: BootstrapAuthConfig) -> str:
        payload = json.encode(config)
        return hashlib.sha256(payload).hexdigest()


class BootstrapRepository:
    """Load bootstrap identities from the database."""

    def __init__(
        self,
        orm: ORM,
        *,
        site: str,
        domain: str,
        secret_resolver: SecretResolver | None = None,
        passkey_cipher: BootstrapPasskeyCipher | None = None,
    ) -> None:
        self._orm = orm
        self._site = site
        self._domain = domain
        self._secret_resolver = secret_resolver
        self._passkey_cipher = passkey_cipher

    async def load(self) -> BootstrapAuthConfig | None:
        tenants = await self._orm.admin.bootstrap_tenants.list(order_by=("slug",))
        admins = await self._orm.admin.bootstrap_admin_users.list(order_by=("email",))
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
            users = await self._orm.tenants.bootstrap_users.list(tenant=context, order_by=("email",))
            tenant_configs.append(
                BootstrapTenant(
                    slug=tenant.slug,
                    name=tenant.name,
                    users=tuple(self._convert_user(user) for user in users),
                )
            )
        admin_users = tuple(self._convert_admin(user) for user in admins)
        admin_realm = BootstrapAdminRealm(users=admin_users)
        return BootstrapAuthConfig(
            tenants=tuple(tenant_configs),
            admin=admin_realm,
            session_ttl_seconds=DEFAULT_BOOTSTRAP_AUTH.session_ttl_seconds,
            flow_ttl_seconds=DEFAULT_BOOTSTRAP_AUTH.flow_ttl_seconds,
            max_attempts=DEFAULT_BOOTSTRAP_AUTH.max_attempts,
        )

    def _convert_user(self, record: BootstrapTenantUserRecord) -> BootstrapUser:
        return BootstrapUser(
            id=record.id,
            email=record.email,
            password=record.password,
            passkeys=self._records_to_passkeys(record.passkeys),
            mfa_code=record.mfa_code,
            sso=record.sso_provider,
        )

    def _convert_admin(self, record: BootstrapAdminUserRecord) -> BootstrapUser:
        return BootstrapUser(
            id=record.id,
            email=record.email,
            password=record.password,
            passkeys=self._records_to_passkeys(record.passkeys),
            mfa_code=record.mfa_code,
        )

    def _records_to_passkeys(self, records: tuple[BootstrapPasskeyRecord, ...]) -> tuple[BootstrapPasskey, ...]:
        return tuple(
            BootstrapPasskey(
                credential_id=record.credential_id,
                secret_ciphertext=SecretValue(literal=record.resolved_secret_ciphertext()),
                label=record.label,
            )
            for record in records
        )

    def decrypt_passkeys(
        self,
        users: Iterable[BootstrapUser],
    ) -> dict[str, tuple[str, bytearray]]:
        return self.extract_passkey_material(
            users,
            cipher=self._passkey_cipher,
            resolver=self._secret_resolver,
        )

    @staticmethod
    def extract_passkey_material(
        users: Iterable[BootstrapUser],
        *,
        cipher: BootstrapPasskeyCipher | None,
        resolver: SecretResolver | None = None,
    ) -> dict[str, tuple[str, bytearray]]:
        """Decrypt passkeys for ``users`` returning mutable buffers."""

        if cipher is None:
            return {}
        material: dict[str, tuple[str, bytearray]] = {}
        for user in users:
            for passkey in user.passkeys:
                ciphertext = passkey.secret_ciphertext.resolve(
                    resolver,
                    field="bootstrap.passkeys.secret_ciphertext",
                )
                if ciphertext is None:
                    raise RuntimeError("Bootstrap passkey ciphertext could not be resolved")
                secret = cipher.decrypt(ciphertext)
                material[passkey.credential_id] = (user.id, secret)
        return material


def _read_env_blob(name: str, env: Mapping[str, str]) -> str | None:
    file_key = f"{name}_FILE"
    path = env.get(file_key)
    if path:
        try:
            return Path(path).read_text(encoding="utf-8")
        except FileNotFoundError as exc:  # pragma: no cover - validated in integration tests
            raise RuntimeError(f"Bootstrap configuration file at '{path}' not found") from exc
    value = env.get(name)
    if value:
        return value
    return None


def load_bootstrap_passkey_cipher(*, env: Mapping[str, str] | None = None) -> BootstrapPasskeyCipher | None:
    """Instantiate a passkey cipher from environment configuration."""

    secret = _read_env_blob("MERE_BOOTSTRAP_PASSPHRASE", env or os.environ)
    if secret is None:
        return None
    return BootstrapPasskeyCipher.from_secret(secret.strip())


def load_bootstrap_auth_from_env(*, env: Mapping[str, str] | None = None) -> BootstrapAuthConfig | None:
    """Decode :class:`BootstrapAuthConfig` material from environment variables."""

    source = _read_env_blob("MERE_BOOTSTRAP_AUTH", env or os.environ)
    if source is None:
        return None
    try:
        payload = json.decode(source)
    except Exception as exc:  # pragma: no cover - defensive surface
        raise RuntimeError("Failed to decode MERE_BOOTSTRAP_AUTH as JSON") from exc
    try:
        return convert(payload, type=BootstrapAuthConfig)
    except Exception as exc:  # pragma: no cover - defensive surface
        raise RuntimeError("Invalid bootstrap auth configuration in environment") from exc


class BootstrapAuthEngine(AuthenticationFlowEngine[AuthenticationFlowUser, BootstrapSession]):
    """Bootstrap authentication engine built on the shared flow orchestration."""

    def __init__(
        self,
        config: BootstrapAuthConfig,
        *,
        passkey_cipher: BootstrapPasskeyCipher | None = None,
        secret_resolver: SecretResolver | None = None,
    ) -> None:
        super().__init__(
            flow_ttl_seconds=config.flow_ttl_seconds,
            session_ttl_seconds=config.session_ttl_seconds,
            max_attempts=config.max_attempts,
        )
        self._passkey_cipher = passkey_cipher
        self._secret_resolver = secret_resolver
        self.config = config
        self._apply_config(config)

    async def reload(self, config: BootstrapAuthConfig) -> None:
        """Replace the engine state with ``config``."""

        async with self._lock:
            self.config = config
            self._apply_config(config)

    def _apply_config(self, config: BootstrapAuthConfig) -> None:
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
        passkey_material = self._collect_passkey_material(records)
        try:
            self.reset(records, passkey_material=passkey_material)
        finally:
            for _, secret in passkey_material.values():
                secret[:] = b"\x00" * len(secret)

    def _collect_passkey_material(
        self, records: Iterable[AuthenticationLoginRecord[AuthenticationFlowUser]]
    ) -> dict[str, tuple[str, bytearray]]:
        if self._passkey_cipher is None:
            return {}
        users = [record.user for record in records]
        return BootstrapRepository.extract_passkey_material(
            users,
            cipher=self._passkey_cipher,
            resolver=self._secret_resolver,
        )

    def _issue_session(self, flow: Any, level: SessionLevel) -> BootstrapSession:
        return BootstrapSession(
            token=f"qs_{generate_id57()}",
            user_id=flow.user.id,
            scope=flow.scope,
            level=level,
            expires_in=self.session_ttl_seconds,
        )


def _default_auth_config() -> BootstrapAuthConfig:
    """Return the built-in bootstrap auth configuration."""

    beta_passkey_ciphertext = _read_env_blob("MERE_BOOTSTRAP_BETA_PASSKEY_CIPHERTEXT", os.environ)
    beta_password = _read_env_blob("MERE_BOOTSTRAP_BETA_PASSWORD", os.environ)
    beta_mfa = _read_env_blob("MERE_BOOTSTRAP_BETA_MFA", os.environ)
    admin_password = _read_env_blob("MERE_BOOTSTRAP_ADMIN_PASSWORD", os.environ)
    admin_mfa = _read_env_blob("MERE_BOOTSTRAP_ADMIN_MFA", os.environ)

    acme_owner = BootstrapUser(
        id="usr_acme_owner",
        email="founder@acme.test",
        sso=BootstrapSsoProvider(
            slug="okta",
            kind="saml",
            display_name="Okta",
            redirect_url="https://id.acme.test/sso/start",
        ),
    )
    beta_passkeys: tuple[BootstrapPasskey, ...] = ()
    if beta_passkey_ciphertext:
        beta_passkeys = (
            BootstrapPasskey(
                credential_id="beta-passkey",
                secret_ciphertext=SecretValue(literal=beta_passkey_ciphertext.strip()),
                label="YubiKey 5",
            ),
        )
    beta_ops = BootstrapUser(
        id="usr_beta_ops",
        email="ops@beta.test",
        password=beta_password,
        passkeys=beta_passkeys,
        mfa_code=beta_mfa,
    )
    admin_root = BootstrapUser(
        id="adm_root",
        email="root@admin.test",
        password=admin_password,
        mfa_code=admin_mfa,
    )
    return BootstrapAuthConfig(
        tenants=(
            BootstrapTenant(slug="acme", name="Acme Rockets", users=(acme_owner,)),
            BootstrapTenant(slug="beta", name="Beta Industries", users=(beta_ops,)),
        ),
        admin=BootstrapAdminRealm(users=(admin_root,)),
    )


DEFAULT_BOOTSTRAP_AUTH: Final[BootstrapAuthConfig] = _default_auth_config()


class BootstrapChatOpsControlPlane:
    """Centralizes ChatOps configuration, normalization, and invocation handling."""

    def __init__(
        self,
        app: MereApp,
        settings: BootstrapChatOpsSettings,
        *,
        command_pattern: RureRegex,
    ) -> None:
        self._app = app
        self._settings = settings
        self._command_pattern = command_pattern
        self._action_bindings: dict[str, str] = {}
        self._binding_actions: dict[str, str] = {}

    @property
    def settings(self) -> BootstrapChatOpsSettings:
        return self._settings

    def register_action_binding(self, action: str, binding_name: str) -> None:
        self._action_bindings[action] = binding_name

    def configure(self, settings: BootstrapChatOpsSettings) -> None:
        """Apply ``settings`` to the ChatOps service and command registry."""

        normalized_commands = self.normalize_commands(settings.slash_commands or _default_slash_commands())
        self._settings = BootstrapChatOpsSettings(
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

    def normalize_command_definition(self, command: BootstrapSlashCommand) -> BootstrapSlashCommand:
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
        return BootstrapSlashCommand(
            name=normalized_name,
            action=command.action,
            description=command.description,
            visibility=command.visibility,
            aliases=tuple(normalized_aliases),
        )

    def normalize_commands(self, commands: Iterable[BootstrapSlashCommand]) -> tuple[BootstrapSlashCommand, ...]:
        normalized: list[BootstrapSlashCommand] = []
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
                command for command in payload.get("slash_commands", []) if command.get("visibility") != "admin"
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
        payload: BootstrapSlashCommandInvocation,
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


class BootstrapAdminControlPlane:
    """Encapsulates admin operations for the bootstrap bundle."""

    def __init__(
        self,
        app: MereApp,
        *,
        slug_normalizer: Callable[[str], str],
        slug_pattern: RureRegex,
        ensure_contexts: Callable[[Iterable[str]], Awaitable[None]],
        chatops: BootstrapChatOpsControlPlane,
        sync_allowed_tenants: Callable[[BootstrapAuthConfig], None],
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
        engine: BootstrapAuthEngine,
        actor: str,
        source: str,
    ) -> BootstrapTenantRecord:
        normalized_slug = self._normalize_slug(slug)
        cleaned_name = name.strip()
        if not normalized_slug or not self._slug_pattern.is_match(normalized_slug):
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_slug"})
        if not cleaned_name:
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_name"})
        if normalized_slug in self._reserved_slugs:
            raise HTTPError(409, {"detail": "slug_reserved"})
        existing = await orm.admin.bootstrap_tenants.get(filters={"slug": normalized_slug})
        if existing is not None:
            raise HTTPError(409, {"detail": "tenant_exists"})
        await self._ensure_contexts([normalized_slug])
        record = await orm.admin.bootstrap_tenants.create({"slug": normalized_slug, "name": cleaned_name})
        tenants_config = [tenant for tenant in engine.config.tenants if tenant.slug != normalized_slug]
        tenants_config.append(BootstrapTenant(slug=normalized_slug, name=cleaned_name, users=()))
        updated_config = BootstrapAuthConfig(
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
        return cast(BootstrapTenantRecord, record)

    async def grant_trial_extension(
        self,
        tenant_slug: str,
        days: int,
        *,
        note: str | None,
        actor: str,
        orm: ORM,
    ) -> BootstrapTrialExtensionRecord:
        normalized_slug = self._normalize_slug(tenant_slug)
        if not normalized_slug or not self._slug_pattern.is_match(normalized_slug):
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_slug"})
        if days <= 0:
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_days"})
        tenant_record = await orm.admin.bootstrap_tenants.get(filters={"slug": normalized_slug})
        if tenant_record is None:
            raise HTTPError(Status.NOT_FOUND, {"detail": "tenant_missing"})
        note_value = note.strip() if note else None
        record = BootstrapTrialExtensionRecord(
            tenant_slug=normalized_slug,
            extended_days=days,
            requested_by=actor,
            note=note_value,
        )
        created = await orm.admin.bootstrap_trial_extensions.create(record)
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
        return cast(BootstrapTrialExtensionRecord, created)

    async def tenant_metrics(self, orm: ORM) -> dict[str, Any]:
        tenants = await orm.admin.bootstrap_tenants.list(order_by=("slug",))
        trials = await orm.admin.bootstrap_trial_extensions.list(order_by=("created_at",))
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
        tenants = await orm.admin.bootstrap_tenants.list(order_by=("slug",))
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
                "open": sum(1 for ticket in tickets if ticket.status != SupportTicketStatus.RESOLVED),
            },
            "allowed_tenants": sorted(self._app.tenant_resolver.allowed_tenants),
        }

    async def create_support_ticket(
        self,
        tenant: TenantContext,
        payload: BootstrapSupportTicketRequest,
        *,
        orm: ORM,
        actor: str,
    ) -> BootstrapSupportTicketRecord:
        subject = payload.subject.strip()
        message = payload.message.strip()
        if not subject or not message:
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_ticket"})
        ticket_kind = SupportTicketKind(payload.kind)
        admin_record = BootstrapSupportTicketRecord(
            tenant_slug=tenant.tenant,
            kind=ticket_kind,
            subject=subject,
            message=message,
        )
        created = await orm.admin.support_tickets.create(admin_record)
        tenant_record = BootstrapTenantSupportTicketRecord(
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
        payload: BootstrapSupportTicketUpdateRequest,
        *,
        orm: ORM,
        actor: str,
    ) -> BootstrapSupportTicketRecord:
        record = await orm.admin.support_tickets.get(filters={"id": ticket_id})
        if record is None:
            raise HTTPError(Status.NOT_FOUND, {"detail": "ticket_missing"})
        status = SupportTicketStatus(payload.status)
        log_entries = list(record.updates)
        if payload.note:
            log_entries.append(
                BootstrapSupportTicketUpdateLog(
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
        if isinstance(updated, Sequence):
            updated_record = cast(
                BootstrapSupportTicketRecord,
                updated[0] if updated else record,
            )
        else:
            updated_record = cast(BootstrapSupportTicketRecord, updated)
        tenant_context = self._app.tenant_resolver.context_for(record.tenant_slug, TenantScope.TENANT)
        tenant_record = await orm.tenants.support_tickets.get(
            tenant=tenant_context,
            filters={"admin_ticket_id": ticket_id},
        )
        if tenant_record is not None:
            tenant_updates = list(tenant_record.updates)
            if payload.note:
                tenant_updates.append(
                    BootstrapSupportTicketUpdateLog(
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
        return updated_record


def attach_bootstrap(
    app: MereApp,
    *,
    base_path: str = "/__mere",
    environment: str | None = None,
    allow_production: bool = False,
    auth_config: BootstrapAuthConfig | None = None,
) -> None:
    """Attach development-only routes for OpenAPI, TypeScript clients, and login orchestration."""

    explicit_environment = environment
    env_source = explicit_environment if explicit_environment is not None else os.getenv("MERE_ENV")
    env = env_source.lower() if env_source else None
    domain = app.config.domain.lower()
    is_dev_env = env in _DEV_ENVIRONMENTS if env is not None else False
    is_dev_domain = domain in _DEV_DOMAINS or any(domain.endswith(suffix) for suffix in _DEV_DOMAIN_SUFFIXES)
    if not allow_production and not (is_dev_env or is_dev_domain):
        if explicit_environment is None:
            # Skip attaching when the environment is unset and the domain is not explicitly development.
            return
        raise RuntimeError("Bootstrap routes are only available in development environments")

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
    diagnostics_path = f"{normalized}/admin/diagnostics" if normalized else "/admin/diagnostics"
    support_admin_path = f"{normalized}/admin/support/tickets" if normalized else "/admin/support/tickets"
    support_admin_ticket_path = f"{support_admin_path}/{{ticket_id}}"
    support_tenant_path = f"{normalized}/support/tickets" if normalized else "/support/tickets"
    tenants_path = f"{normalized}/tenants" if normalized else "/tenants"
    chatops_settings_path = f"{normalized}/admin/chatops" if normalized else "/admin/chatops"
    chatops_slash_path = f"{normalized}/chatops/slash" if normalized else "/chatops/slash"
    workspaces_path = f"{normalized}/workspaces" if normalized else "/workspaces"
    tiles_collection_path = f"{workspaces_path}/{{wsId}}/tiles"
    tile_item_path = f"{tiles_collection_path}/{{tileId}}"
    tile_permissions_path = f"{tile_item_path}/permissions"
    workspace_settings_path = f"{workspaces_path}/{{wsId}}/settings"
    workspace_notifications_path = f"{workspaces_path}/{{wsId}}/notifications"
    workspace_kanban_path = f"{workspaces_path}/{{wsId}}/kanban"
    rbac_permission_sets_path = f"{workspaces_path}/{{wsId}}/rbac/permission-sets"
    rbac_role_assign_path = f"{workspaces_path}/{{wsId}}/rbac/roles/{{roleId}}/assign"
    delegations_path = f"{normalized}/delegations" if normalized else "/delegations"
    delegation_item_path = f"{delegations_path}/{{delegationId}}"
    audit_logs_path = f"{workspaces_path}/{{wsId}}/audit-logs"
    audit_logs_export_path = f"{audit_logs_path}/export"

    env_auth_config = load_bootstrap_auth_from_env()
    seed_hint = auth_config or env_auth_config or DEFAULT_BOOTSTRAP_AUTH
    passkey_cipher = load_bootstrap_passkey_cipher()
    secret_resolver = getattr(app.database, "_secret_resolver", None) if app.database else None

    def _sync_allowed_tenants(config: BootstrapAuthConfig) -> None:
        resolver = app.tenant_resolver
        resolver.allowed_tenants.update(tenant.slug for tenant in config.tenants)
        resolver.allowed_tenants.discard(app.config.admin_subdomain)
        resolver.allowed_tenants.discard(app.config.marketing_tenant)

    _sync_allowed_tenants(seed_hint)

    engine = BootstrapAuthEngine(
        seed_hint,
        passkey_cipher=passkey_cipher,
        secret_resolver=secret_resolver,
    )
    app.dependencies.provide(BootstrapAuthEngine, lambda: engine)

    if app.database and app.orm:
        database = cast(Database, app.database)
        orm = cast(ORM, app.orm)
        initial_chatops_config = app.chatops.config
        initial_chatops_settings = BootstrapChatOpsSettings(
            enabled=initial_chatops_config.enabled,
            webhook=(initial_chatops_config.default if initial_chatops_config.enabled else None),
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
            migrations=bootstrap_migrations(),
            tenant_provider=lambda: list(tenants_map.values()),
        )
        seeder = BootstrapSeeder(orm, secret_resolver=secret_resolver)
        repository = BootstrapRepository(
            orm,
            site=app.config.site,
            domain=app.config.domain,
            secret_resolver=secret_resolver,
            passkey_cipher=passkey_cipher,
        )

        tile_domain = BootstrapTileService(orm)
        rbac_domain = BootstrapRbacService(orm)
        delegation_domain = BootstrapDelegationService(orm)
        audit_domain = BootstrapAuditService(orm)

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

        def _assert_workspace_access(request: Request, workspace_id: str) -> None:
            if request.tenant.scope is TenantScope.TENANT and request.tenant.tenant != workspace_id:
                raise HTTPError(Status.FORBIDDEN, {"detail": "workspace_forbidden"})

        def _resolve_workspace_context(workspace_id: str) -> TenantContext:
            context = tenants_map.get(workspace_id)
            if context is None:
                context = TenantContext(
                    tenant=workspace_id,
                    site=app.config.site,
                    domain=app.config.domain,
                    scope=TenantScope.TENANT,
                )
                tenants_map[workspace_id] = context
            return context

        async def _collect_workspace_notifications(
            orm: ORM | None,
            workspace_id: str,
        ) -> tuple[BootstrapNotification, ...]:
            if orm is None:
                return _sample_notification_feed(workspace_id)
            notifications: list[BootstrapNotification] = []
            trials = await orm.admin.bootstrap_trial_extensions.list(
                filters={"tenant_slug": workspace_id},
                order_by=("created_at desc",),
            )
            for record in trials:
                notifications.append(
                    BootstrapNotification(
                        id=f"trial-{record.id}",
                        workspace_id=workspace_id,
                        kind="trial",
                        title="Trial extended",
                        message=f"Trial extended by {record.extended_days} days",
                        occurred_at=record.updated_at,
                        actor=record.requested_by,
                        severity="info",
                        metadata={"days": record.extended_days},
                    )
                )
            tickets = await orm.admin.support_tickets.list(
                filters={"tenant_slug": workspace_id},
                order_by=("updated_at desc",),
            )
            for ticket in tickets:
                latest_note = ticket.updates[-1].note if ticket.updates else ticket.message
                severity = "info"
                if ticket.status is SupportTicketStatus.RESPONDED:
                    severity = "warning"
                elif ticket.status is SupportTicketStatus.RESOLVED:
                    severity = "info"
                notifications.append(
                    BootstrapNotification(
                        id=f"ticket-{ticket.id}",
                        workspace_id=workspace_id,
                        kind="support",
                        title=ticket.subject,
                        message=latest_note or ticket.message,
                        occurred_at=ticket.updated_at,
                        actor=ticket.updated_by,
                        severity="critical" if ticket.status is SupportTicketStatus.OPEN else severity,
                        metadata={
                            "ticketId": ticket.id,
                            "status": ticket.status.value,
                        },
                    )
                )
            billing_records = await orm.admin.billing.list(
                filters={"customer_id": workspace_id},
                order_by=("updated_at desc",),
            )
            for record in billing_records:
                if record.status is BillingStatus.PAST_DUE:
                    severity = "critical"
                    message = "Subscription payment is past due"
                elif record.status is BillingStatus.CANCELED:
                    severity = "warning"
                    message = "Subscription canceled"
                else:
                    severity = "info"
                    message = f"Plan {record.plan_code} is {record.status.value}"
                notifications.append(
                    BootstrapNotification(
                        id=f"billing-{record.id}",
                        workspace_id=workspace_id,
                        kind="billing",
                        title="Billing update",
                        message=message,
                        occurred_at=record.updated_at,
                        severity=severity,
                        metadata={
                            "status": record.status.value,
                            "amountDueCents": record.amount_due_cents,
                        },
                    )
                )
            if not notifications:
                return _sample_notification_feed(workspace_id)
            notifications.sort(key=lambda item: item.occurred_at, reverse=True)
            return tuple(notifications)

        async def _load_workspace_board(
            orm: ORM | None,
            workspace_id: str,
            tenant_ctx: TenantContext,
        ) -> BootstrapKanbanBoard:
            if orm is None:
                return _sample_kanban_board(workspace_id)
            tickets = await orm.tenants.support_tickets.list(
                tenant=tenant_ctx,
                order_by=("updated_at desc",),
            )
            if not tickets:
                return _sample_kanban_board(workspace_id)
            columns: dict[str, list[BootstrapKanbanCard]] = {key: [] for key in _KANBAN_COLUMN_TITLES}
            latest = _SAMPLE_FEED_BASE
            for ticket in tickets:
                column_key = _KANBAN_STATUS_BY_TICKET.get(ticket.status, "backlog")
                severity = _KANBAN_SEVERITY_BY_KIND.get(ticket.kind, "low")
                card = BootstrapKanbanCard(
                    id=ticket.id,
                    title=ticket.subject,
                    status=column_key,
                    created_at=ticket.created_at,
                    updated_at=ticket.updated_at,
                    assignee=ticket.updated_by,
                    tags=(ticket.kind.value,),
                    summary=ticket.message,
                    severity=severity,
                )
                columns[column_key].append(card)
                if card.updated_at > latest:
                    latest = card.updated_at
            if not any(columns.values()):
                return _sample_kanban_board(workspace_id)
            column_payload = tuple(
                BootstrapKanbanColumn(
                    key=key,
                    title=_KANBAN_COLUMN_TITLES[key],
                    cards=tuple(columns[key]),
                )
                for key in ("backlog", "in_progress", "done")
            )
            return BootstrapKanbanBoard(
                workspace_id=workspace_id,
                columns=column_payload,
                updated_at=latest,
            )

        async def _bootstrap_bootstrap() -> None:
            await _ensure_contexts_for(tenants_map.keys())
            config_to_load: BootstrapAuthConfig
            source_config = auth_config or env_auth_config
            if source_config is not None:
                config_to_load = source_config
                await _ensure_contexts_for(tenant.slug for tenant in config_to_load.tenants)
                await seeder.apply(config_to_load, tenants=tenants_map)
            else:
                loaded = await repository.load()
                if loaded is None:
                    config_to_load = DEFAULT_BOOTSTRAP_AUTH
                    await _ensure_contexts_for(tenant.slug for tenant in config_to_load.tenants)
                    await seeder.apply(config_to_load, tenants=tenants_map)
                else:
                    config_to_load = loaded
                    await _ensure_contexts_for(tenant.slug for tenant in config_to_load.tenants)
            await engine.reload(config_to_load)
            _sync_allowed_tenants(config_to_load)

        app.on_startup(_bootstrap_bootstrap)

        def _require_admin(request: Request) -> None:
            if request.tenant.scope is not TenantScope.ADMIN:
                raise HTTPError(Status.FORBIDDEN, {"detail": "admin_required"})

        def _normalize_slug(raw: str) -> str:
            return raw.strip().lower()

        chatops_control = BootstrapChatOpsControlPlane(
            app,
            initial_chatops_settings,
            command_pattern=_TENANT_SLUG_PATTERN,
        )
        chatops_control.configure(initial_chatops_settings)

        admin_control = BootstrapAdminControlPlane(
            app,
            slug_normalizer=_normalize_slug,
            slug_pattern=_TENANT_SLUG_PATTERN,
            ensure_contexts=_ensure_contexts_for,
            chatops=chatops_control,
            sync_allowed_tenants=_sync_allowed_tenants,
        )

        chatops_control.register_action_binding("create_tenant", "bootstrap.chatops.create_tenant")
        chatops_control.register_action_binding("extend_trial", "bootstrap.chatops.extend_trial")
        chatops_control.register_action_binding("tenant_metrics", "bootstrap.chatops.tenant_metrics")
        chatops_control.register_action_binding("system_diagnostics", "bootstrap.chatops.system_diagnostics")
        chatops_control.register_action_binding("ticket_update", "bootstrap.chatops.ticket_update")

        @app.chatops_command(
            ChatOpsSlashCommand(
                name="create-tenant",
                description="Provision a new tenant from Slack.",
                visibility="admin",
                aliases=("bootstrap-create-tenant",),
            ),
            name="bootstrap.chatops.create_tenant",
        )
        async def bootstrap_chatops_create_tenant_command(
            context: ChatOpsCommandContext,
        ) -> dict[str, Any]:
            slug_arg = context.args.get("slug")
            name_arg = context.args.get("name")
            if not slug_arg or not name_arg:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "missing_arguments"})
            orm = await context.dependencies.get(ORM)
            engine = await context.dependencies.get(BootstrapAuthEngine)
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
                aliases=("bootstrap-extend-trial",),
            ),
            name="bootstrap.chatops.extend_trial",
        )
        async def bootstrap_chatops_extend_trial_command(
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
                aliases=("bootstrap-tenant-metrics",),
            ),
            name="bootstrap.chatops.tenant_metrics",
        )
        async def bootstrap_chatops_tenant_metrics_command(
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
                description="Display bootstrap diagnostics and health checks.",
                visibility="admin",
                aliases=("bootstrap-system-diagnostics",),
            ),
            name="bootstrap.chatops.system_diagnostics",
        )
        async def bootstrap_chatops_system_diagnostics_command(
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
                aliases=("bootstrap-ticket-update",),
            ),
            name="bootstrap.chatops.ticket_update",
        )
        async def bootstrap_chatops_ticket_update_command(
            context: ChatOpsCommandContext,
        ) -> dict[str, Any]:
            ticket_id = context.args.get("ticket")
            status_arg = context.args.get("status")
            if not ticket_id or not status_arg:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "missing_arguments"})
            if status_arg not in {"open", "responded", "resolved"}:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_status"})
            update_payload = BootstrapSupportTicketUpdateRequest(status=status_arg, note=context.args.get("note"))
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

        @app.get(tiles_collection_path, name="bootstrap_tiles_list")
        async def bootstrap_tiles_list(
            request: Request,
            wsId: str,
            service: TileService,
        ) -> tuple[TileRecord, ...]:
            _assert_workspace_access(request, wsId)
            return await service.list_tiles(
                tenant=request.tenant,
                workspace_id=wsId,
                principal=request.principal,
            )

        @app.post(tiles_collection_path, name="bootstrap_tiles_create")
        async def bootstrap_tiles_create(
            request: Request,
            wsId: str,
            payload: TileCreate,
            service: TileService,
        ) -> Response:
            _assert_workspace_access(request, wsId)
            result = await service.create_tile(
                tenant=request.tenant,
                workspace_id=wsId,
                principal=request.principal,
                payload=payload,
            )
            return JSONResponse(to_builtins(result), status=int(Status.CREATED))

        _register_response_model(
            bootstrap_tiles_create,
            status=int(Status.CREATED),
            model=TileRecord,
            description="Tile created",
        )

        @app.get(tile_item_path, name="bootstrap_tiles_read")
        async def bootstrap_tiles_read(
            request: Request,
            wsId: str,
            tileId: str,
            service: TileService,
        ) -> TileRecord:
            _assert_workspace_access(request, wsId)
            return await service.get_tile(
                tenant=request.tenant,
                workspace_id=wsId,
                tile_id=tileId,
                principal=request.principal,
            )

        @app.route(tile_item_path, methods=("PATCH",), name="bootstrap_tiles_update")
        async def bootstrap_tiles_update(
            request: Request,
            wsId: str,
            tileId: str,
            payload: TileUpdate,
            service: TileService,
        ) -> TileRecord:
            _assert_workspace_access(request, wsId)
            result = await service.update_tile(
                tenant=request.tenant,
                workspace_id=wsId,
                tile_id=tileId,
                principal=request.principal,
                payload=payload,
            )
            return result

        @app.route(tile_item_path, methods=("DELETE",), name="bootstrap_tiles_delete")
        async def bootstrap_tiles_delete(
            request: Request,
            wsId: str,
            tileId: str,
            service: TileService,
        ) -> None:
            _assert_workspace_access(request, wsId)
            await service.delete_tile(
                tenant=request.tenant,
                workspace_id=wsId,
                tile_id=tileId,
                principal=request.principal,
            )
            return None

        @app.route(
            tile_permissions_path,
            methods=("PUT",),
            name="bootstrap_tiles_permissions",
        )
        async def bootstrap_tiles_permissions(
            request: Request,
            wsId: str,
            tileId: str,
            payload: TilePermissions,
            service: TileService,
        ) -> TilePermissions:
            _assert_workspace_access(request, wsId)
            result = await service.set_permissions(
                tenant=request.tenant,
                workspace_id=wsId,
                tile_id=tileId,
                principal=request.principal,
                permissions=payload,
            )
            return result

        @app.get(workspace_settings_path, name="bootstrap_workspace_settings")
        async def bootstrap_workspace_settings(
            request: Request,
            wsId: str,
            orm: ORM,
            service: TileService,
        ) -> BootstrapWorkspaceSettings:
            _assert_workspace_access(request, wsId)
            tiles = await service.list_tiles(
                tenant=request.tenant,
                workspace_id=wsId,
                principal=request.principal,
            )
            tile_count = len(tiles)
            ai_enabled = any(tile.ai_insights_enabled for tile in tiles)
            tenant_record = await orm.admin.bootstrap_tenants.get(filters={"slug": wsId})
            workspace_name = tenant_record.name if tenant_record else wsId.replace("-", " ").title()
            notifications = await _collect_workspace_notifications(orm, wsId)
            alerts = tuple(
                notification.id for notification in notifications if notification.severity in {"warning", "critical"}
            )
            return BootstrapWorkspaceSettings(
                workspace_id=wsId,
                name=workspace_name,
                timezone="UTC",
                currency="USD",
                features=("analytics", "kanban", "support", "delegations"),
                tile_count=tile_count,
                ai_insights_enabled=ai_enabled,
                alerts=alerts,
            )

        @app.get(workspace_notifications_path, name="bootstrap_workspace_notifications")
        async def bootstrap_workspace_notifications(
            request: Request,
            wsId: str,
            orm: ORM,
        ) -> tuple[BootstrapNotification, ...]:
            _assert_workspace_access(request, wsId)
            return await _collect_workspace_notifications(orm, wsId)

        @app.get(workspace_kanban_path, name="bootstrap_workspace_kanban")
        async def bootstrap_workspace_kanban(
            request: Request,
            wsId: str,
            orm: ORM,
        ) -> BootstrapKanbanBoard:
            _assert_workspace_access(request, wsId)
            tenant_context = _resolve_workspace_context(wsId)
            return await _load_workspace_board(orm, wsId, tenant_context)

        @app.post(
            rbac_permission_sets_path,
            name="bootstrap_rbac_permission_sets_create",
        )
        async def bootstrap_rbac_permission_sets_create(
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

        _register_response_model(
            bootstrap_rbac_permission_sets_create,
            status=int(Status.CREATED),
            model=PermissionSetRecord,
            description="Permission set created",
        )

        @app.post(rbac_role_assign_path, name="bootstrap_rbac_assign_role")
        async def bootstrap_rbac_assign_role(
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

        @app.post(delegations_path, name="bootstrap_delegations_grant")
        async def bootstrap_delegations_grant(
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

        _register_response_model(
            bootstrap_delegations_grant,
            status=int(Status.CREATED),
            model=DelegationRecord,
            description="Delegation granted",
        )

        @app.route(
            delegation_item_path,
            methods=("DELETE",),
            name="bootstrap_delegations_revoke",
        )
        async def bootstrap_delegations_revoke(
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

        @app.get(audit_logs_path, name="bootstrap_audit_logs")
        async def bootstrap_audit_logs(
            request: Request,
            wsId: str,
            service: AuditService,
        ) -> Response:
            _require_admin(request)
            query = request.query(BootstrapAuditLogQuery)
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

        @app.get(audit_logs_export_path, name="bootstrap_audit_logs_export")
        async def bootstrap_audit_logs_export(
            request: Request,
            wsId: str,
            service: AuditService,
        ) -> Response:
            _require_admin(request)
            query = request.query(BootstrapAuditLogQuery)
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

        @app.get(billing_path, name="bootstrap_admin_billing")
        async def bootstrap_admin_billing(request: Request, orm: ORM) -> Response:
            _require_admin(request)
            records = await orm.admin.billing.list(order_by=("created_at desc",))
            return JSONResponse(tuple(to_builtins(record) for record in records))

        @app.post(billing_path, name="bootstrap_admin_create_billing")
        async def bootstrap_admin_create_billing(
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

        _register_response_model(
            bootstrap_admin_create_billing,
            status=int(Status.CREATED),
            model=BillingRecord,
            description="Billing record created",
        )

        @app.get(metrics_path, name="bootstrap_admin_metrics")
        async def bootstrap_admin_metrics(request: Request, orm: ORM) -> Response:
            _require_admin(request)
            metrics = await admin_control.tenant_metrics(orm)
            return JSONResponse(metrics)

        @app.get(diagnostics_path, name="bootstrap_admin_diagnostics")
        async def bootstrap_admin_diagnostics(request: Request, orm: ORM) -> Response:
            _require_admin(request)
            diagnostics = await admin_control.system_diagnostics(orm)
            return JSONResponse(diagnostics)

        @app.get(support_admin_path, name="bootstrap_admin_support_tickets")
        async def bootstrap_admin_support_tickets(request: Request, orm: ORM) -> Response:
            _require_admin(request)
            tickets = await orm.admin.support_tickets.list(order_by=("created_at desc",))
            return JSONResponse(tuple(to_builtins(ticket) for ticket in tickets))

        @app.post(
            support_admin_ticket_path,
            name="bootstrap_admin_support_ticket_update",
        )
        async def bootstrap_admin_support_ticket_update(
            request: Request,
            ticket_id: str,
            payload: BootstrapSupportTicketUpdateRequest,
            orm: ORM,
        ) -> Response:
            _require_admin(request)
            updated = await admin_control.update_support_ticket(
                ticket_id,
                payload,
                orm=orm,
                actor=request.headers.get("x-mere-actor", "bootstrap-admin"),
            )
            return JSONResponse(to_builtins(updated))

        @app.get(support_tenant_path, name="bootstrap_tenant_support_tickets")
        async def bootstrap_tenant_support_tickets(request: Request, orm: ORM) -> Response:
            if request.tenant.scope is TenantScope.ADMIN:
                return JSONResponse(())
            tickets = await orm.tenants.support_tickets.list(
                tenant=request.tenant,
                order_by=("created_at desc",),
            )
            return JSONResponse(tuple(to_builtins(ticket) for ticket in tickets))

        @app.post(support_tenant_path, name="bootstrap_tenant_create_support_ticket")
        async def bootstrap_tenant_create_support_ticket(
            request: Request,
            payload: BootstrapSupportTicketRequest,
            orm: ORM,
        ) -> Response:
            if request.tenant.scope is not TenantScope.TENANT:
                raise HTTPError(Status.FORBIDDEN, {"detail": "tenant_required"})
            actor = request.headers.get("x-mere-actor", request.tenant.tenant)
            ticket = await admin_control.create_support_ticket(
                request.tenant,
                payload,
                orm=orm,
                actor=actor,
            )
            return JSONResponse(to_builtins(ticket), status=201)

        @app.get(tenants_path, name="bootstrap_tenants")
        async def bootstrap_list_tenants(request: Request, orm: ORM) -> Response:
            if request.tenant.scope is TenantScope.ADMIN:
                records = await orm.admin.bootstrap_tenants.list(order_by=("slug",))
            else:
                record = await orm.admin.bootstrap_tenants.get(filters={"slug": request.tenant.tenant})
                records = [] if record is None else [record]
            return JSONResponse(tuple(to_builtins(record) for record in records))

        @app.post(tenants_path, name="bootstrap_create_tenant")
        async def bootstrap_create_tenant(
            request: Request,
            payload: BootstrapTenantCreateRequest,
            orm: ORM,
            engine: BootstrapAuthEngine,
        ) -> Response:
            _require_admin(request)
            actor = request.headers.get("x-mere-actor", "bootstrap-admin")
            record = await admin_control.create_tenant_from_inputs(
                payload.slug,
                payload.name,
                orm=orm,
                engine=engine,
                actor=actor,
                source="api",
            )
            return JSONResponse(to_builtins(record), status=201)

        @app.get(chatops_settings_path, name="bootstrap_admin_chatops_settings")
        async def bootstrap_admin_chatops_settings(
            request: Request,
        ) -> Response:
            _require_admin(request)
            settings = chatops_control.serialize_settings()
            return JSONResponse(settings)

        @app.post(chatops_settings_path, name="bootstrap_admin_update_chatops_settings")
        async def bootstrap_update_chatops_settings(
            request: Request,
            payload: BootstrapChatOpsSettings,
        ) -> Response:
            _require_admin(request)
            if payload.enabled and payload.webhook is None:
                raise HTTPError(Status.BAD_REQUEST, {"detail": "webhook_required"})
            commands_iterable = payload.slash_commands or _default_slash_commands()
            normalized_commands = chatops_control.normalize_commands(commands_iterable)
            settings = BootstrapChatOpsSettings(
                enabled=payload.enabled,
                webhook=payload.webhook,
                notifications=payload.notifications,
                slash_commands=normalized_commands,
                bot_user_id=payload.bot_user_id,
                admin_workspace=payload.admin_workspace,
            )
            chatops_control.configure(settings)
            return JSONResponse(chatops_control.serialize_settings())

        @app.post(chatops_slash_path, name="bootstrap_chatops_slash")
        async def bootstrap_chatops_slash(
            request: Request,
            payload: BootstrapSlashCommandInvocation,
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

    @app.get(ping_path, name="bootstrap_ping")
    async def bootstrap_ping() -> str:
        return "pong"

    @app.get(openapi_path, name="bootstrap_openapi")
    async def bootstrap_openapi() -> Response:
        spec = generate_openapi(app)
        return JSONResponse(spec)

    @app.get(client_path, name="bootstrap_client")
    async def bootstrap_client() -> Response:
        spec = generate_openapi(app)
        source = generate_typescript_client(spec)
        return Response(
            headers=(("content-type", "application/typescript"),),
            body=source.encode("utf-8"),
        )

    @app.post(login_start_path, name="bootstrap_login_start")
    async def bootstrap_login_start(
        request: Request, payload: LoginStartRequest, engine: BootstrapAuthEngine
    ) -> BootstrapLoginResponse:
        result = await engine.start(request.tenant, email=payload.email)
        return result

    @app.post(passkey_path, name="bootstrap_login_passkey")
    async def bootstrap_login_passkey(
        request: Request, payload: PasskeyAttempt, engine: BootstrapAuthEngine
    ) -> BootstrapLoginResponse:
        result = await engine.passkey(request.tenant, payload)
        return result

    @app.post(password_path, name="bootstrap_login_password")
    async def bootstrap_login_password(
        request: Request, payload: PasswordAttempt, engine: BootstrapAuthEngine
    ) -> BootstrapLoginResponse:
        result = await engine.password(request.tenant, payload)
        return result

    @app.post(mfa_path, name="bootstrap_login_mfa")
    async def bootstrap_login_mfa(
        request: Request, payload: MfaAttempt, engine: BootstrapAuthEngine
    ) -> BootstrapLoginResponse:
        result = await engine.mfa(request.tenant, payload)
        return result


__all__ = [
    "DEFAULT_BOOTSTRAP_AUTH",
    "BillingCreateRequest",
    "BootstrapAdminControlPlane",
    "BootstrapAdminRealm",
    "BootstrapAdminUserRecord",
    "BootstrapAuthConfig",
    "BootstrapAuthEngine",
    "BootstrapChatOpsControlPlane",
    "BootstrapChatOpsNotificationChannels",
    "BootstrapChatOpsSettings",
    "BootstrapKanbanBoard",
    "BootstrapKanbanCard",
    "BootstrapKanbanColumn",
    "BootstrapLoginResponse",
    "BootstrapNotification",
    "BootstrapPasskey",
    "BootstrapPasskeyCipher",
    "BootstrapPasskeyRecord",
    "BootstrapRepository",
    "BootstrapSeedStateRecord",
    "BootstrapSeeder",
    "BootstrapSession",
    "BootstrapSlashCommand",
    "BootstrapSlashCommandInvocation",
    "BootstrapSsoProvider",
    "BootstrapSupportTicketRecord",
    "BootstrapSupportTicketRequest",
    "BootstrapSupportTicketUpdateLog",
    "BootstrapSupportTicketUpdateRequest",
    "BootstrapTenant",
    "BootstrapTenantCreateRequest",
    "BootstrapTenantRecord",
    "BootstrapTenantSupportTicketRecord",
    "BootstrapTenantUserRecord",
    "BootstrapTrialExtensionRecord",
    "BootstrapUser",
    "BootstrapWorkspaceSettings",
    "LoginStep",
    "MfaAttempt",
    "PasskeyAttempt",
    "PasswordAttempt",
    "attach_bootstrap",
    "bootstrap_migrations",
    "ensure_tenant_schemas",
    "load_bootstrap_auth_from_env",
    "load_bootstrap_passkey_cipher",
]
