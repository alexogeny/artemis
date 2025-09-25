"""Built-in Artemis models for admin and tenant schemas with ``id57`` identifiers."""

from __future__ import annotations

import datetime as dt
from enum import Enum
from typing import TYPE_CHECKING, Any

import msgspec

from .orm import DatabaseModel, ModelScope, model

if TYPE_CHECKING:  # pragma: no cover - used only for type checking
    from .database import SecretRef, SecretResolver
else:  # pragma: no cover - runtime import avoided in type checking
    from .database import SecretRef


class BillingStatus(str, Enum):
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"


@model(scope=ModelScope.ADMIN, table="billing")
class BillingRecord(DatabaseModel):
    customer_id: str
    plan_code: str
    status: BillingStatus
    amount_due_cents: int
    currency: str
    cycle_start: dt.datetime
    cycle_end: dt.datetime
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)


class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAUSED = "paused"
    CANCELED = "canceled"


@model(scope=ModelScope.ADMIN, table="subscriptions")
class Subscription(DatabaseModel):
    customer_id: str
    billing_id: str
    product_code: str
    status: SubscriptionStatus
    seats: int
    current_period_end: dt.datetime


@model(
    scope=ModelScope.ADMIN,
    table="app_secrets",
    exposed=False,
    redacted_fields=("secret", "salt"),
)
class AppSecret(DatabaseModel):
    secret: SecretRef
    salt: str
    rotated_at: dt.datetime | None = None

    def resolve_secret(self, resolver: "SecretResolver") -> str:
        """Resolve the external secret backing this record."""

        return resolver.resolve(self.secret)


@model(scope=ModelScope.ADMIN, table="customers", redacted_fields=("tenant_secret",))
class Customer(DatabaseModel):
    tenant: str
    schema_name: str
    billing_id: str
    status: str
    tenant_secret: SecretRef
    contact_email: str | None = None

    def resolve_tenant_secret(self, resolver: "SecretResolver") -> str:
        """Resolve the external secret protecting this tenant."""

        return resolver.resolve(self.tenant_secret)


class RoleScope(str, Enum):
    ADMIN = "admin"
    TENANT = "tenant"


@model(scope=ModelScope.ADMIN, table="roles")
class Role(DatabaseModel):
    name: str
    scope: RoleScope
    tenant: str | None = None
    description: str | None = None


class PermissionEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@model(scope=ModelScope.ADMIN, table="permissions")
class Permission(DatabaseModel):
    role_id: str
    action: str
    resource_type: str
    effect: PermissionEffect = PermissionEffect.ALLOW
    condition: dict[str, Any] = msgspec.field(default_factory=dict)


@model(
    scope=ModelScope.ADMIN,
    table="admin_users",
    redacted_fields=(
        "hashed_password",
        "password_salt",
        "password_secret",
        "mfa_enforced",
        "mfa_enrolled_at",
    ),
)
class AdminUser(DatabaseModel):
    email: str
    hashed_password: str
    password_salt: str = ""
    password_secret: str = ""
    is_active: bool = True
    last_sign_in_at: dt.datetime | None = None
    mfa_enforced: bool = False
    mfa_enrolled_at: dt.datetime | None = None


@model(scope=ModelScope.ADMIN, table="admin_role_assignments")
class AdminRoleAssignment(DatabaseModel):
    admin_user_id: str
    role_id: str
    assigned_at: dt.datetime


@model(
    scope=ModelScope.ADMIN,
    table="admin_passkeys",
    exposed=False,
    redacted_fields=(
        "credential_id",
        "public_key",
        "attestation_format",
        "sign_count",
        "last_used_at",
    ),
)
class AdminPasskey(DatabaseModel):
    admin_user_id: str
    credential_id: str
    public_key: str
    attestation_format: str | None = None
    sign_count: int = 0
    last_used_at: dt.datetime | None = None
    label: str | None = None


@model(
    scope=ModelScope.TENANT,
    table="tenant_secrets",
    exposed=False,
    redacted_fields=("secret",),
)
class TenantSecret(DatabaseModel):
    secret: SecretRef
    rotated_at: dt.datetime | None = None
    purpose: str = "password"

    def resolve_secret(self, resolver: "SecretResolver") -> str:
        """Resolve the external secret backing this tenant."""

        return resolver.resolve(self.secret)


@model(
    scope=ModelScope.TENANT,
    table="users",
    redacted_fields=(
        "hashed_password",
        "password_salt",
        "password_secret",
        "mfa_enforced",
        "mfa_enrolled_at",
    ),
)
class TenantUser(DatabaseModel):
    email: str
    hashed_password: str
    username: str = ""
    password_salt: str = ""
    password_secret: str = ""
    is_active: bool = True
    last_sign_in_at: dt.datetime | None = None
    mfa_enforced: bool = False
    mfa_enrolled_at: dt.datetime | None = None
    federated_subjects: list[str] = msgspec.field(default_factory=list)


@model(scope=ModelScope.TENANT, table="user_roles")
class UserRole(DatabaseModel):
    user_id: str
    role_id: str
    assigned_at: dt.datetime


@model(scope=ModelScope.TENANT, table="custom_permissions")
class CustomPermission(DatabaseModel):
    code: str
    action: str
    resource_type: str
    effect: PermissionEffect = PermissionEffect.ALLOW
    description: str | None = None


class SessionLevel(str, Enum):
    PASSWORD_ONLY = "password_only"
    MFA = "mfa"
    PASSKEY = "passkey"


@model(
    scope=ModelScope.TENANT,
    table="session_tokens",
    exposed=False,
    redacted_fields=("token_hash", "token_salt"),
)
class SessionToken(DatabaseModel):
    user_id: str
    token_hash: str
    token_salt: str
    expires_at: dt.datetime
    level: SessionLevel
    revoked_at: dt.datetime | None = None


@model(
    scope=ModelScope.TENANT,
    table="passkeys",
    exposed=False,
    redacted_fields=(
        "credential_id",
        "public_key",
        "user_handle",
        "attestation_format",
        "sign_count",
        "last_used_at",
        "transports",
    ),
)
class Passkey(DatabaseModel):
    user_id: str
    credential_id: str
    public_key: str
    user_handle: str
    attestation_format: str | None = None
    sign_count: int = 0
    last_used_at: dt.datetime | None = None
    transports: list[str] = msgspec.field(default_factory=list)
    label: str | None = None


class MfaPurpose(str, Enum):
    SIGN_IN = "sign_in"
    RECOVERY = "recovery"
    ENROLLMENT = "enrollment"


@model(
    scope=ModelScope.TENANT,
    table="mfa_codes",
    exposed=False,
    redacted_fields=("code",),
)
class MfaCode(DatabaseModel):
    user_id: str
    code: str
    purpose: MfaPurpose
    expires_at: dt.datetime
    consumed_at: dt.datetime | None = None
    channel: str = "totp"


class FederatedProvider(str, Enum):
    OIDC = "oidc"
    SAML = "saml"


@model(
    scope=ModelScope.TENANT,
    table="oidc_providers",
    redacted_fields=("client_secret",),
)
class TenantOidcProvider(DatabaseModel):
    issuer: str
    client_id: str
    jwks_uri: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    client_secret: SecretRef | None = None
    enabled: bool = True
    allowed_audiences: list[str] = msgspec.field(default_factory=list)
    allowed_groups: list[str] = msgspec.field(default_factory=list)

    def resolve_client_secret(self, resolver: "SecretResolver") -> str:
        """Resolve the client secret backing this provider."""

        if self.client_secret is None:
            raise LookupError("OIDC client secret not configured")
        return resolver.resolve(self.client_secret)


@model(scope=ModelScope.TENANT, table="saml_providers")
class TenantSamlProvider(DatabaseModel):
    entity_id: str
    metadata_url: str
    certificate: str
    acs_url: str
    enabled: bool = True
    attribute_mapping: dict[str, str] = msgspec.field(default_factory=dict)
    clock_skew_seconds: int = 120
    allowed_audiences: list[str] = msgspec.field(default_factory=list)


@model(scope=ModelScope.TENANT, table="federated_users")
class TenantFederatedUser(DatabaseModel):
    provider_id: str
    provider_type: FederatedProvider
    subject: str
    user_id: str


@model(scope=ModelScope.ADMIN, table="admin_audit_log")
class AdminAuditLogEntry(DatabaseModel):
    action: str
    entity_type: str
    entity_id: str | None = None
    actor_id: str | None = None
    actor_type: str | None = None
    changes: dict[str, Any] = msgspec.field(default_factory=dict)
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)


@model(scope=ModelScope.TENANT, table="audit_log")
class TenantAuditLogEntry(DatabaseModel):
    action: str
    entity_type: str
    entity_id: str | None = None
    actor_id: str | None = None
    actor_type: str | None = None
    changes: dict[str, Any] = msgspec.field(default_factory=dict)
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)


__all__ = [
    "AdminAuditLogEntry",
    "AdminPasskey",
    "AdminRoleAssignment",
    "AdminUser",
    "AppSecret",
    "BillingRecord",
    "BillingStatus",
    "CustomPermission",
    "Customer",
    "FederatedProvider",
    "MfaCode",
    "MfaPurpose",
    "Passkey",
    "Permission",
    "PermissionEffect",
    "Role",
    "RoleScope",
    "SessionLevel",
    "SessionToken",
    "Subscription",
    "SubscriptionStatus",
    "TenantAuditLogEntry",
    "TenantFederatedUser",
    "TenantOidcProvider",
    "TenantSamlProvider",
    "TenantSecret",
    "TenantUser",
    "UserRole",
]
