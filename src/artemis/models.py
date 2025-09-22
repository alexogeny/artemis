"""Built-in Artemis models for admin and tenant schemas."""

from __future__ import annotations

import datetime as dt
import uuid
from enum import Enum
from typing import Any

import msgspec

from .orm import Model, ModelScope, model


class BillingStatus(str, Enum):
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"


@model(scope=ModelScope.ADMIN, table="billing")
class BillingRecord(Model):
    id: uuid.UUID
    customer_id: uuid.UUID
    plan_code: str
    status: BillingStatus
    amount_due_cents: int
    currency: str
    cycle_start: dt.datetime
    cycle_end: dt.datetime
    created_at: dt.datetime
    updated_at: dt.datetime
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)


class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAUSED = "paused"
    CANCELED = "canceled"


@model(scope=ModelScope.ADMIN, table="subscriptions")
class Subscription(Model):
    id: uuid.UUID
    customer_id: uuid.UUID
    billing_id: uuid.UUID
    product_code: str
    status: SubscriptionStatus
    seats: int
    current_period_end: dt.datetime
    created_at: dt.datetime
    updated_at: dt.datetime


@model(scope=ModelScope.ADMIN, table="admin_users")
class AdminUser(Model):
    id: uuid.UUID
    email: str
    hashed_password: str
    created_at: dt.datetime
    updated_at: dt.datetime
    is_active: bool = True
    last_sign_in_at: dt.datetime | None = None


@model(scope=ModelScope.ADMIN, table="admin_role_assignments")
class AdminRoleAssignment(Model):
    id: uuid.UUID
    admin_user_id: uuid.UUID
    role_id: uuid.UUID
    assigned_at: dt.datetime


@model(scope=ModelScope.ADMIN, table="customers")
class Customer(Model):
    id: uuid.UUID
    tenant: str
    schema_name: str
    billing_id: uuid.UUID
    status: str
    created_at: dt.datetime
    updated_at: dt.datetime


@model(scope=ModelScope.ADMIN, table="app_secrets")
class AppSecret(Model):
    id: uuid.UUID
    secret_hash: str
    created_at: dt.datetime
    rotated_at: dt.datetime | None = None


class RoleScope(str, Enum):
    ADMIN = "admin"
    TENANT = "tenant"


@model(scope=ModelScope.ADMIN, table="roles")
class Role(Model):
    id: uuid.UUID
    name: str
    scope: RoleScope
    created_at: dt.datetime
    updated_at: dt.datetime
    tenant: str | None = None
    description: str | None = None


class PermissionEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@model(scope=ModelScope.ADMIN, table="permissions")
class Permission(Model):
    id: uuid.UUID
    role_id: uuid.UUID
    action: str
    resource_type: str
    created_at: dt.datetime
    updated_at: dt.datetime
    effect: PermissionEffect = PermissionEffect.ALLOW
    condition: dict[str, Any] = msgspec.field(default_factory=dict)


@model(scope=ModelScope.TENANT, table="users")
class TenantUser(Model):
    id: uuid.UUID
    email: str
    hashed_password: str
    created_at: dt.datetime
    updated_at: dt.datetime
    is_active: bool = True
    last_sign_in_at: dt.datetime | None = None


@model(scope=ModelScope.TENANT, table="user_roles")
class UserRole(Model):
    id: uuid.UUID
    user_id: uuid.UUID
    role_id: uuid.UUID
    assigned_at: dt.datetime


@model(scope=ModelScope.TENANT, table="custom_permissions")
class CustomPermission(Model):
    id: uuid.UUID
    code: str
    action: str
    resource_type: str
    created_at: dt.datetime
    updated_at: dt.datetime
    effect: PermissionEffect = PermissionEffect.ALLOW
    description: str | None = None


@model(scope=ModelScope.TENANT, table="session_tokens")
class SessionToken(Model):
    id: uuid.UUID
    user_id: uuid.UUID
    token: str
    expires_at: dt.datetime
    created_at: dt.datetime
    revoked_at: dt.datetime | None = None


@model(scope=ModelScope.TENANT, table="passkeys")
class Passkey(Model):
    id: uuid.UUID
    user_id: uuid.UUID
    credential_id: str
    public_key: str
    created_at: dt.datetime
    attestation_format: str | None = None
    sign_count: int = 0
    last_used_at: dt.datetime | None = None


@model(scope=ModelScope.TENANT, table="mfa_codes")
class MfaCode(Model):
    id: uuid.UUID
    user_id: uuid.UUID
    code: str
    purpose: str
    expires_at: dt.datetime
    created_at: dt.datetime
    consumed_at: dt.datetime | None = None


__all__ = [
    "AdminRoleAssignment",
    "AdminUser",
    "AppSecret",
    "BillingRecord",
    "BillingStatus",
    "CustomPermission",
    "Customer",
    "MfaCode",
    "Passkey",
    "Permission",
    "PermissionEffect",
    "Role",
    "RoleScope",
    "SessionToken",
    "Subscription",
    "SubscriptionStatus",
    "TenantUser",
    "UserRole",
]
