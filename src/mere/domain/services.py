"""Domain service contracts used by the bootstrap transport layer."""

from __future__ import annotations

from datetime import datetime
from typing import Mapping, Protocol, Sequence

import msgspec

from ..rbac import CedarEntity
from ..tenancy import TenantContext


class TilePermissions(msgspec.Struct, frozen=True, omit_defaults=True):
    """Explicit access policy for a dashboard tile."""

    roles: tuple[str, ...] = ()
    users: tuple[str, ...] = ()


class TileCreate(msgspec.Struct, frozen=True, omit_defaults=True):
    """Payload for creating a dashboard tile."""

    title: str
    layout: Mapping[str, object]
    description: str | None = None
    data_sources: tuple[str, ...] = ()
    ai_insights_enabled: bool = False


class TileUpdate(msgspec.Struct, frozen=True, omit_defaults=True):
    """Partial update payload for a dashboard tile."""

    title: str | None = None
    layout: Mapping[str, object] | None = None
    description: str | None = None
    data_sources: tuple[str, ...] | None = None
    ai_insights_enabled: bool | None = None


class TileRecord(msgspec.Struct, frozen=True, omit_defaults=True):
    """Canonical representation of a dashboard tile."""

    id: str
    workspace_id: str
    title: str
    layout: Mapping[str, object]
    description: str | None = None
    data_sources: tuple[str, ...] = ()
    ai_insights_enabled: bool = False
    permissions: TilePermissions | None = None
    metadata: Mapping[str, object] | None = None


class TileService(Protocol):
    """Manage dashboard tiles while enforcing RBAC."""

    async def list_tiles(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal: CedarEntity | None,
    ) -> tuple[TileRecord, ...]: ...

    async def get_tile(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal: CedarEntity | None,
    ) -> TileRecord: ...

    async def create_tile(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal: CedarEntity | None,
        payload: TileCreate,
    ) -> TileRecord: ...

    async def update_tile(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal: CedarEntity | None,
        payload: TileUpdate,
    ) -> TileRecord: ...

    async def delete_tile(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal: CedarEntity | None,
    ) -> None: ...

    async def set_permissions(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal: CedarEntity | None,
        permissions: TilePermissions,
    ) -> TilePermissions: ...

    async def toggle_ai_insights(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal: CedarEntity | None,
        enabled: bool,
    ) -> TileRecord: ...


class PermissionSetCreate(msgspec.Struct, frozen=True, omit_defaults=True):
    """Definition for a custom permission set."""

    name: str
    permissions: tuple[str, ...]
    description: str | None = None
    create_role: bool = True


class PermissionSetRecord(msgspec.Struct, frozen=True, omit_defaults=True):
    """Resolved permission set details."""

    id: str
    workspace_id: str
    name: str
    permissions: tuple[str, ...]
    role_id: str
    description: str | None = None


class RoleAssignment(msgspec.Struct, frozen=True, omit_defaults=True):
    """Role assignment payload for workspace users."""

    user_ids: tuple[str, ...] = msgspec.field(name="userIds", default_factory=tuple)


class RoleAssignmentResult(msgspec.Struct, frozen=True, omit_defaults=True):
    """Outcome of assigning a role to a collection of users."""

    role_id: str
    workspace_id: str
    assigned_user_ids: tuple[str, ...]


class RbacService(Protocol):
    """Manage workspace RBAC state (custom roles, permission sets)."""

    async def create_permission_set(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal: CedarEntity | None,
        payload: PermissionSetCreate,
    ) -> PermissionSetRecord: ...

    async def assign_role(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        role_id: str,
        principal: CedarEntity | None,
        payload: RoleAssignment,
    ) -> RoleAssignmentResult: ...


class DelegationGrant(msgspec.Struct, frozen=True, omit_defaults=True):
    """Request payload for granting time-bound permissions."""

    from_user_id: str = msgspec.field(name="fromUserId")
    to_user_id: str = msgspec.field(name="toUserId")
    scopes: tuple[str, ...]
    workspace_id: str = msgspec.field(name="workspaceId")
    starts_at: datetime = msgspec.field(name="startsAt")
    ends_at: datetime = msgspec.field(name="endsAt")


class DelegationRecord(msgspec.Struct, frozen=True, omit_defaults=True):
    """Active delegation details."""

    id: str
    from_user_id: str
    to_user_id: str
    scopes: tuple[str, ...]
    workspace_id: str = msgspec.field(name="workspaceId")
    starts_at: datetime
    ends_at: datetime
    created_by: str


class DelegationService(Protocol):
    """Handle permission delegations across principals."""

    async def grant(
        self,
        *,
        tenant: TenantContext,
        principal: CedarEntity | None,
        payload: DelegationGrant,
    ) -> DelegationRecord: ...

    async def revoke(
        self,
        *,
        tenant: TenantContext,
        principal: CedarEntity | None,
        delegation_id: str,
    ) -> None: ...

    async def list_active(
        self,
        *,
        tenant: TenantContext,
        principal: CedarEntity | None,
        user_id: str | None = None,
        workspace_id: str | None = None,
    ) -> Sequence[DelegationRecord]: ...

    async def resolve_effective_permissions(
        self,
        *,
        tenant: TenantContext,
        principal: CedarEntity | None,
        user_id: str,
        workspace_id: str | None = None,
    ) -> tuple[str, ...]: ...


class AuditLogEntry(msgspec.Struct, frozen=True, omit_defaults=True):
    """Serialized audit log entry."""

    id: str
    timestamp: datetime
    actor: str
    action: str
    entity_type: str
    entity_id: str | None = None
    metadata: Mapping[str, object] = msgspec.field(default_factory=dict)


class AuditLogPage(msgspec.Struct, frozen=True, omit_defaults=True):
    """Page of audit log entries with optional pagination cursor."""

    entries: tuple[AuditLogEntry, ...]
    next_token: str | None = None


class AuditLogExportQuery(msgspec.Struct, frozen=True, omit_defaults=True):
    """Export configuration for audit log downloads."""

    format: str = "json"


class AuditLogExport(msgspec.Struct, frozen=True, omit_defaults=True):
    """Exported audit log artifact."""

    content_type: str
    body: bytes
    filename: str | None = None


class AuditService(Protocol):
    """Read and export audit information."""

    async def read(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal: CedarEntity | None,
        actor: str | None = None,
        action: str | None = None,
        entity: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
    ) -> AuditLogPage: ...

    async def export(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal: CedarEntity | None,
        query: AuditLogExportQuery,
        actor: str | None = None,
        action: str | None = None,
        entity: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
    ) -> AuditLogExport: ...
