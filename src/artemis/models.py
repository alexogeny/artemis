"""Built-in Artemis models for admin and tenant schemas with ``id57`` identifiers."""

from __future__ import annotations

import datetime as dt
from enum import Enum
from typing import Any

import msgspec

from .id57 import generate_id57
from .orm import Model, ModelScope, model


class BillingStatus(str, Enum):
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"


@model(scope=ModelScope.ADMIN, table="billing")
class BillingRecord(Model):
    customer_id: str
    plan_code: str
    status: BillingStatus
    amount_due_cents: int
    currency: str
    cycle_start: dt.datetime
    cycle_end: dt.datetime
    created_at: dt.datetime
    updated_at: dt.datetime
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)
    id: str = msgspec.field(default_factory=generate_id57)


class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAUSED = "paused"
    CANCELED = "canceled"


@model(scope=ModelScope.ADMIN, table="subscriptions")
class Subscription(Model):
    customer_id: str
    billing_id: str
    product_code: str
    status: SubscriptionStatus
    seats: int
    current_period_end: dt.datetime
    created_at: dt.datetime
    updated_at: dt.datetime
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.ADMIN, table="app_secrets")
class AppSecret(Model):
    secret_value: str
    salt: str
    created_at: dt.datetime
    rotated_at: dt.datetime | None = None
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.ADMIN, table="customers")
class Customer(Model):
    tenant: str
    schema_name: str
    billing_id: str
    status: str
    created_at: dt.datetime
    updated_at: dt.datetime
    tenant_secret: str
    contact_email: str | None = None
    id: str = msgspec.field(default_factory=generate_id57)


class RoleScope(str, Enum):
    ADMIN = "admin"
    TENANT = "tenant"


@model(scope=ModelScope.ADMIN, table="roles")
class Role(Model):
    name: str
    scope: RoleScope
    created_at: dt.datetime
    updated_at: dt.datetime
    tenant: str | None = None
    description: str | None = None
    id: str = msgspec.field(default_factory=generate_id57)


class PermissionEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@model(scope=ModelScope.ADMIN, table="permissions")
class Permission(Model):
    role_id: str
    action: str
    resource_type: str
    created_at: dt.datetime
    updated_at: dt.datetime
    effect: PermissionEffect = PermissionEffect.ALLOW
    condition: dict[str, Any] = msgspec.field(default_factory=dict)
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.ADMIN, table="admin_users")
class AdminUser(Model):
    email: str
    hashed_password: str
    created_at: dt.datetime
    updated_at: dt.datetime
    password_salt: str = ""
    password_secret: str = ""
    is_active: bool = True
    last_sign_in_at: dt.datetime | None = None
    mfa_enforced: bool = False
    mfa_enrolled_at: dt.datetime | None = None
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.ADMIN, table="admin_role_assignments")
class AdminRoleAssignment(Model):
    admin_user_id: str
    role_id: str
    assigned_at: dt.datetime
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.ADMIN, table="admin_passkeys")
class AdminPasskey(Model):
    admin_user_id: str
    credential_id: str
    public_key: str
    created_at: dt.datetime
    attestation_format: str | None = None
    sign_count: int = 0
    last_used_at: dt.datetime | None = None
    label: str | None = None
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.TENANT, table="tenant_secrets")
class TenantSecret(Model):
    secret: str
    created_at: dt.datetime
    rotated_at: dt.datetime | None = None
    purpose: str = "password"
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.TENANT, table="users")
class TenantUser(Model):
    email: str
    hashed_password: str
    created_at: dt.datetime
    updated_at: dt.datetime
    username: str = ""
    password_salt: str = ""
    password_secret: str = ""
    is_active: bool = True
    last_sign_in_at: dt.datetime | None = None
    mfa_enforced: bool = False
    mfa_enrolled_at: dt.datetime | None = None
    federated_subjects: list[str] = msgspec.field(default_factory=list)
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.TENANT, table="user_roles")
class UserRole(Model):
    user_id: str
    role_id: str
    assigned_at: dt.datetime
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.TENANT, table="custom_permissions")
class CustomPermission(Model):
    code: str
    action: str
    resource_type: str
    created_at: dt.datetime
    updated_at: dt.datetime
    effect: PermissionEffect = PermissionEffect.ALLOW
    description: str | None = None
    id: str = msgspec.field(default_factory=generate_id57)


class SessionLevel(str, Enum):
    PASSWORD_ONLY = "password_only"
    MFA = "mfa"
    PASSKEY = "passkey"


@model(scope=ModelScope.TENANT, table="session_tokens")
class SessionToken(Model):
    user_id: str
    token: str
    expires_at: dt.datetime
    created_at: dt.datetime
    level: SessionLevel
    revoked_at: dt.datetime | None = None
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.TENANT, table="passkeys")
class Passkey(Model):
    user_id: str
    credential_id: str
    public_key: str
    user_handle: str
    created_at: dt.datetime
    attestation_format: str | None = None
    sign_count: int = 0
    last_used_at: dt.datetime | None = None
    transports: list[str] = msgspec.field(default_factory=list)
    label: str | None = None
    id: str = msgspec.field(default_factory=generate_id57)


class MfaPurpose(str, Enum):
    SIGN_IN = "sign_in"
    RECOVERY = "recovery"
    ENROLLMENT = "enrollment"


@model(scope=ModelScope.TENANT, table="mfa_codes")
class MfaCode(Model):
    user_id: str
    code: str
    purpose: MfaPurpose
    expires_at: dt.datetime
    created_at: dt.datetime
    consumed_at: dt.datetime | None = None
    channel: str = "totp"
    id: str = msgspec.field(default_factory=generate_id57)


class FederatedProvider(str, Enum):
    OIDC = "oidc"
    SAML = "saml"


@model(scope=ModelScope.TENANT, table="oidc_providers")
class TenantOidcProvider(Model):
    issuer: str
    client_id: str
    client_secret: str
    jwks_uri: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    created_at: dt.datetime
    updated_at: dt.datetime
    enabled: bool = True
    allowed_audiences: list[str] = msgspec.field(default_factory=list)
    allowed_groups: list[str] = msgspec.field(default_factory=list)
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.TENANT, table="saml_providers")
class TenantSamlProvider(Model):
    entity_id: str
    metadata_url: str
    certificate: str
    acs_url: str
    created_at: dt.datetime
    updated_at: dt.datetime
    enabled: bool = True
    attribute_mapping: dict[str, str] = msgspec.field(default_factory=dict)
    id: str = msgspec.field(default_factory=generate_id57)


@model(scope=ModelScope.TENANT, table="federated_users")
class TenantFederatedUser(Model):
    provider_id: str
    provider_type: FederatedProvider
    subject: str
    user_id: str
    created_at: dt.datetime
    updated_at: dt.datetime
    id: str = msgspec.field(default_factory=generate_id57)


__all__ = [
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
    "TenantFederatedUser",
    "TenantOidcProvider",
    "TenantSamlProvider",
    "TenantSecret",
    "TenantUser",
    "UserRole",
]

