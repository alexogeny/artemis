"""Concrete domain services powering the quickstart experience."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Sequence

from msgspec import Struct, json, to_builtins

from ..exceptions import HTTPError
from ..http import Status
from ..models import (
    DashboardTile,
    DashboardTilePermission,
    Permission,
    PermissionEffect,
    Role,
    RoleScope,
    WorkspacePermissionDelegation,
    WorkspacePermissionSet,
    WorkspaceRoleAssignment,
)
from ..orm import ORM
from ..rbac import CedarEffect, CedarEngine, CedarPolicy, CedarReference
from ..tenancy import TenantContext, TenantScope
from .services import (
    AuditLogEntry,
    AuditLogExport,
    AuditLogExportQuery,
    AuditLogPage,
    AuditService,
    DelegationGrant,
    DelegationRecord,
    DelegationService,
    PermissionSetCreate,
    PermissionSetRecord,
    RbacService,
    RoleAssignment,
    RoleAssignmentResult,
    TileCreate,
    TilePermissions,
    TileRecord,
    TileService,
    TileUpdate,
)


class _Clock(Struct, frozen=True):
    now: Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _tenant_for_workspace(current: TenantContext, workspace_id: str) -> TenantContext:
    if current.scope is TenantScope.TENANT and current.tenant == workspace_id:
        return current
    return TenantContext(
        tenant=workspace_id,
        site=current.site,
        domain=current.domain,
        scope=TenantScope.TENANT,
    )


def _to_tile_record(
    tile: DashboardTile,
    permission: DashboardTilePermission | None,
) -> TileRecord:
    perms = None
    if permission is not None:
        perms = TilePermissions(roles=permission.roles, users=permission.users)
    return TileRecord(
        id=tile.id,
        workspace_id=tile.workspace_id,
        title=tile.title,
        layout=tile.layout,
        description=tile.description,
        data_sources=tile.data_sources,
        ai_insights_enabled=tile.ai_insights_enabled,
        permissions=perms,
        metadata=tile.metadata,
    )


class QuickstartTileService(TileService):
    """Persist dashboard tiles using the ORM."""

    def __init__(self, orm: ORM) -> None:
        self._orm = orm

    async def create_tile(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal,
        payload: TileCreate,
    ) -> TileRecord:
        target = _tenant_for_workspace(tenant, workspace_id)
        tile = await self._orm.tenants.dashboard_tiles.create(
            DashboardTile(
                workspace_id=workspace_id,
                title=payload.title,
                layout=dict(payload.layout),
                description=payload.description,
                data_sources=payload.data_sources,
                ai_insights_enabled=payload.ai_insights_enabled,
            ),
            tenant=target,
        )
        return await self._load_tile(target, tile.id)

    async def update_tile(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal,
        payload: TileUpdate,
    ) -> TileRecord:
        target = _tenant_for_workspace(tenant, workspace_id)
        values: dict[str, object] = {}
        if payload.title is not None:
            values["title"] = payload.title
        if payload.layout is not None:
            values["layout"] = dict(payload.layout)
        if payload.description is not None:
            values["description"] = payload.description
        if payload.data_sources is not None:
            values["data_sources"] = payload.data_sources
        if payload.ai_insights_enabled is not None:
            values["ai_insights_enabled"] = payload.ai_insights_enabled
        if not values:
            return await self._load_tile(target, tile_id)
        updated = await self._orm.tenants.dashboard_tiles.update(
            values,
            tenant=target,
            filters={"id": tile_id},
        )
        if not updated:
            raise HTTPError(Status.NOT_FOUND, {"detail": "tile_missing"})
        return await self._load_tile(target, tile_id)

    async def delete_tile(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal,
    ) -> None:
        target = _tenant_for_workspace(tenant, workspace_id)
        await self._orm.tenants.dashboard_tile_permissions.delete(
            tenant=target,
            filters={"tile_id": tile_id},
        )
        removed = await self._orm.tenants.dashboard_tiles.delete(
            tenant=target,
            filters={"id": tile_id},
        )
        if not removed:
            raise HTTPError(Status.NOT_FOUND, {"detail": "tile_missing"})

    async def set_permissions(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal,
        permissions: TilePermissions,
    ) -> TilePermissions:
        target = _tenant_for_workspace(tenant, workspace_id)
        existing = await self._orm.tenants.dashboard_tile_permissions.get(
            tenant=target,
            filters={"tile_id": tile_id},
        )
        payload = {
            "roles": permissions.roles,
            "users": permissions.users,
        }
        if existing is None:
            await self._orm.tenants.dashboard_tile_permissions.create(
                DashboardTilePermission(tile_id=tile_id, **payload),
                tenant=target,
            )
        else:
            await self._orm.tenants.dashboard_tile_permissions.update(
                payload,
                tenant=target,
                filters={"id": existing.id},
            )
        return permissions

    async def toggle_ai_insights(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        tile_id: str,
        principal,
        enabled: bool,
    ) -> TileRecord:
        target = _tenant_for_workspace(tenant, workspace_id)
        updated = await self._orm.tenants.dashboard_tiles.update(
            {"ai_insights_enabled": enabled},
            tenant=target,
            filters={"id": tile_id},
        )
        if not updated:
            raise HTTPError(Status.NOT_FOUND, {"detail": "tile_missing"})
        return await self._load_tile(target, tile_id)

    async def _load_tile(self, tenant: TenantContext, tile_id: str) -> TileRecord:
        tile = await self._orm.tenants.dashboard_tiles.get(
            tenant=tenant,
            filters={"id": tile_id},
        )
        if tile is None:
            raise HTTPError(Status.NOT_FOUND, {"detail": "tile_missing"})
        permission = await self._orm.tenants.dashboard_tile_permissions.get(
            tenant=tenant,
            filters={"tile_id": tile.id},
        )
        return _to_tile_record(tile, permission)


class QuickstartRbacService(RbacService):
    """Manage custom permission sets for workspaces."""

    def __init__(self, orm: ORM, clock: Callable[[], datetime] | None = None) -> None:
        self._orm = orm
        self._clock = _Clock(now=clock or _utcnow)

    async def create_permission_set(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal,
        payload: PermissionSetCreate,
    ) -> PermissionSetRecord:
        target = _tenant_for_workspace(tenant, workspace_id)
        existing = await self._orm.tenants.workspace_permission_sets.get(
            tenant=target,
            filters={"workspace_id": workspace_id, "name": payload.name},
        )
        if existing is not None:
            raise HTTPError(409, {"detail": "permission_set_exists"})
        normalized_scopes = tuple(dict.fromkeys(payload.permissions))
        role = await self._orm.admin.roles.create(
            Role(
                name=f"{workspace_id}:{payload.name}",
                scope=RoleScope.TENANT,
                tenant=workspace_id,
                description=payload.description,
            )
        )
        for scope in normalized_scopes:
            await self._orm.admin.permissions.create(
                Permission(
                    role_id=role.id,
                    action=scope,
                    resource_type="workspace",
                    effect=PermissionEffect.ALLOW,
                )
            )
        record = await self._orm.tenants.workspace_permission_sets.create(
            WorkspacePermissionSet(
                workspace_id=workspace_id,
                name=payload.name,
                permissions=normalized_scopes,
                description=payload.description,
                role_id=role.id,
            ),
            tenant=target,
        )
        return PermissionSetRecord(
            id=record.id,
            workspace_id=record.workspace_id,
            name=record.name,
            permissions=record.permissions,
            role_id=record.role_id or role.id,
            description=record.description,
        )

    async def assign_role(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        role_id: str,
        principal,
        payload: RoleAssignment,
    ) -> RoleAssignmentResult:
        target = _tenant_for_workspace(tenant, workspace_id)
        permission_set = await self._orm.tenants.workspace_permission_sets.get(
            tenant=target,
            filters={"workspace_id": workspace_id, "role_id": role_id},
        )
        if permission_set is None:
            raise HTTPError(Status.NOT_FOUND, {"detail": "permission_set_missing"})
        now = self._clock.now()
        assigned_ids: list[str] = []
        for user_id in payload.user_ids:
            existing = await self._orm.tenants.workspace_role_assignments.get(
                tenant=target,
                filters={"workspace_id": workspace_id, "role_id": role_id, "user_id": user_id},
            )
            if existing is not None:
                assigned_ids.append(user_id)
                continue
            await self._orm.tenants.workspace_role_assignments.create(
                WorkspaceRoleAssignment(
                    workspace_id=workspace_id,
                    role_id=role_id,
                    user_id=user_id,
                    assigned_at=now,
                ),
                tenant=target,
            )
            assigned_ids.append(user_id)
        return RoleAssignmentResult(
            role_id=role_id,
            workspace_id=workspace_id,
            assigned_user_ids=tuple(assigned_ids),
        )


class QuickstartDelegationService(DelegationService):
    """Store delegations and expose effective permissions."""

    def __init__(self, orm: ORM, clock: Callable[[], datetime] | None = None) -> None:
        self._orm = orm
        self._clock = _Clock(now=clock or _utcnow)

    async def grant(
        self,
        *,
        tenant: TenantContext,
        principal,
        payload: DelegationGrant,
    ) -> DelegationRecord:
        target = _tenant_for_workspace(tenant, payload.workspace_id)
        if payload.starts_at >= payload.ends_at:
            raise HTTPError(Status.BAD_REQUEST, {"detail": "invalid_window"})
        grantor_scopes = set(
            await self.resolve_effective_permissions(
                tenant=target,
                principal=principal,
                user_id=payload.from_user_id,
                workspace_id=payload.workspace_id,
            )
        )
        missing = [scope for scope in payload.scopes if scope not in grantor_scopes]
        if missing:
            raise HTTPError(
                Status.FORBIDDEN,
                {"detail": "scope_not_granted", "scopes": missing},
            )
        manager = self._orm.tenants.permission_delegations
        overlapping = await manager.list(
            tenant=target,
            filters={
                "workspace_id": payload.workspace_id,
                "from_user_id": payload.from_user_id,
                "to_user_id": payload.to_user_id,
            },
        )
        record: WorkspacePermissionDelegation | None = None
        for candidate in overlapping:
            if candidate.ends_at < payload.starts_at or candidate.starts_at > payload.ends_at:
                continue
            merged_scopes = tuple(sorted(set(candidate.scopes) | set(payload.scopes)))
            new_start = min(candidate.starts_at, payload.starts_at)
            new_end = max(candidate.ends_at, payload.ends_at)
            updated = await manager.update(
                {
                    "scopes": merged_scopes,
                    "starts_at": new_start,
                    "ends_at": new_end,
                },
                tenant=target,
                filters={"id": candidate.id},
            )
            record = updated[0]
            break
        if record is None:
            created = await manager.create(
                WorkspacePermissionDelegation(
                    workspace_id=payload.workspace_id,
                    from_user_id=payload.from_user_id,
                    to_user_id=payload.to_user_id,
                    scopes=tuple(sorted(set(payload.scopes))),
                    starts_at=payload.starts_at,
                    ends_at=payload.ends_at,
                ),
                tenant=target,
            )
            record = created
        return self._to_record(record)

    async def revoke(
        self,
        *,
        tenant: TenantContext,
        principal,
        delegation_id: str,
    ) -> None:
        now = self._clock.now()
        if tenant.scope is not TenantScope.TENANT:
            raise HTTPError(Status.FORBIDDEN, {"detail": "tenant_required"})
        updated = await self._orm.tenants.permission_delegations.update(
            {"ends_at": now},
            tenant=tenant,
            filters={"id": delegation_id},
        )
        if not updated:
            raise HTTPError(Status.NOT_FOUND, {"detail": "delegation_missing"})

    async def list_active(
        self,
        *,
        tenant: TenantContext,
        principal,
        user_id: str | None = None,
        workspace_id: str | None = None,
    ) -> Sequence[DelegationRecord]:
        now = self._clock.now()
        filters: dict[str, object] = {}
        if workspace_id is not None:
            filters["workspace_id"] = workspace_id
        if user_id is not None:
            filters["to_user_id"] = user_id
        target = tenant if workspace_id is None else _tenant_for_workspace(tenant, workspace_id)
        if target.scope is not TenantScope.TENANT:
            raise HTTPError(Status.FORBIDDEN, {"detail": "tenant_required"})
        entries = await self._orm.tenants.permission_delegations.list(
            tenant=target,
            filters=filters or None,
        )
        return tuple(
            self._to_record(item)
            for item in entries
            if item.starts_at <= now <= item.ends_at
        )

    async def resolve_effective_permissions(
        self,
        *,
        tenant: TenantContext,
        principal,
        user_id: str,
        workspace_id: str | None = None,
    ) -> tuple[str, ...]:
        target = tenant if workspace_id is None else _tenant_for_workspace(tenant, workspace_id)
        if target.scope is not TenantScope.TENANT:
            raise HTTPError(Status.FORBIDDEN, {"detail": "tenant_required"})
        sets = await self._orm.tenants.workspace_permission_sets.list(
            tenant=target,
            filters={"workspace_id": workspace_id} if workspace_id else None,
        )
        assignments = await self._orm.tenants.workspace_role_assignments.list(
            tenant=target,
            filters={"workspace_id": workspace_id, "user_id": user_id}
            if workspace_id
            else {"user_id": user_id},
        )
        permission_map = {record.role_id: record for record in sets}
        scopes: set[str] = set()
        for assignment in assignments:
            record = permission_map.get(assignment.role_id)
            if record is None:
                continue
            scopes.update(record.permissions)
        now = self._clock.now()
        delegations = await self._orm.tenants.permission_delegations.list(
            tenant=target,
            filters={"to_user_id": user_id},
        )
        for delegation in delegations:
            if workspace_id is not None and delegation.workspace_id != workspace_id:
                continue
            if not (delegation.starts_at <= now <= delegation.ends_at):
                continue
            scopes.update(delegation.scopes)
        return tuple(sorted(scopes))

    @staticmethod
    def _to_record(record: WorkspacePermissionDelegation) -> DelegationRecord:
        return DelegationRecord(
            id=record.id,
            from_user_id=record.from_user_id,
            to_user_id=record.to_user_id,
            scopes=record.scopes,
            workspace_id=record.workspace_id,
            starts_at=record.starts_at,
            ends_at=record.ends_at,
            created_by=record.created_by or "system",
        )


class QuickstartAuditService(AuditService):
    """Adapter that materializes audit data from tenant tables."""

    def __init__(self, orm: ORM) -> None:
        self._orm = orm

    async def read(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal,
        actor: str | None = None,
        action: str | None = None,
        entity: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
    ) -> AuditLogPage:
        target = _tenant_for_workspace(tenant, workspace_id)
        entries = await self._orm.tenants.audit_log.list(
            tenant=target,
            order_by=("created_at desc",),
        )
        filtered = [
            entry
            for entry in entries
            if _matches(entry, actor=actor, action=action, entity=entity, from_time=from_time, to_time=to_time)
        ]
        return AuditLogPage(
            entries=tuple(
                AuditLogEntry(
                    id=entry.id,
                    timestamp=entry.created_at,
                    actor=_audit_actor_label(entry.actor_id, entry.actor_type, tenant),
                    action=entry.action,
                    entity_type=entry.entity_type,
                    entity_id=entry.entity_id,
                    metadata=to_builtins(entry.metadata),
                )
                for entry in filtered
            ),
        )

    async def export(
        self,
        *,
        tenant: TenantContext,
        workspace_id: str,
        principal,
        query: AuditLogExportQuery,
        actor: str | None = None,
        action: str | None = None,
        entity: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
    ) -> AuditLogExport:
        page = await self.read(
            tenant=tenant,
            workspace_id=workspace_id,
            principal=principal,
            actor=actor,
            action=action,
            entity=entity,
            from_time=from_time,
            to_time=to_time,
        )
        if query.format == "csv":
            header = "id,timestamp,actor,action,entity_type,entity_id\n"
            rows = [
                ",".join(
                    (
                        entry.id,
                        entry.timestamp.isoformat(),
                        entry.actor,
                        entry.action,
                        entry.entity_type,
                        entry.entity_id or "",
                    )
                )
                for entry in page.entries
            ]
            body = (header + "\n".join(rows)).encode("utf-8")
            return AuditLogExport(
                content_type="text/csv",
                body=body,
                filename=f"audit-{workspace_id}.csv",
            )
        return AuditLogExport(
            content_type="application/json",
            body=json.encode(to_builtins(page)),
            filename=None,
        )


def _matches(
    entry,
    *,
    actor: str | None,
    action: str | None,
    entity: str | None,
    from_time: datetime | None,
    to_time: datetime | None,
) -> bool:
    if actor and entry.actor_id != actor:
        return False
    if action and entry.action != action:
        return False
    if entity and entry.entity_type != entity:
        return False
    if from_time and entry.created_at < from_time:
        return False
    if to_time and entry.created_at > to_time:
        return False
    return True


def _audit_actor_label(
    actor_id: str | None,
    actor_type: str | None,
    tenant: TenantContext,
) -> str:
    if actor_type == "sysadmin":
        return f"{tenant.site} {tenant.domain} sysadmin"
    return actor_id or "unknown"


async def build_cedar_engine(
    orm: ORM,
    *,
    tenant: TenantContext,
    at: datetime | None = None,
) -> CedarEngine:
    reference = at or _utcnow()
    if tenant.scope is not TenantScope.TENANT:
        raise HTTPError(Status.FORBIDDEN, {"detail": "tenant_required"})
    permission_sets = await orm.tenants.workspace_permission_sets.list(tenant=tenant)
    assignments = await orm.tenants.workspace_role_assignments.list(tenant=tenant)
    delegations = await orm.tenants.permission_delegations.list(tenant=tenant)
    sets_by_role = {record.role_id: record for record in permission_sets}
    policies: list[CedarPolicy] = []
    for assignment in assignments:
        record = sets_by_role.get(assignment.role_id)
        if record is None:
            continue
        for scope in record.permissions:
            policies.append(
                CedarPolicy(
                    effect=CedarEffect.ALLOW,
                    principal=CedarReference("User", assignment.user_id),
                    actions=(scope,),
                    resource=CedarReference("workspace", record.workspace_id),
                )
            )
    for delegation in delegations:
        if not (delegation.starts_at <= reference <= delegation.ends_at):
            continue
        for scope in delegation.scopes:
            policies.append(
                CedarPolicy(
                    effect=CedarEffect.ALLOW,
                    principal=CedarReference("User", delegation.to_user_id),
                    actions=(scope,),
                    resource=CedarReference("workspace", delegation.workspace_id),
                )
            )
    return CedarEngine(policies)
