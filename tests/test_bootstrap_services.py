from __future__ import annotations

import datetime as dt
from collections import defaultdict
from typing import Any, Iterable, cast

import pytest
from msgspec import Struct, structs

from mere.domain.bootstrap_services import (
    BootstrapAuditService,
    BootstrapDelegationService,
    BootstrapRbacService,
    BootstrapTileService,
    build_cedar_engine,
)
from mere.domain.services import (
    AuditLogExportQuery,
    DelegationGrant,
    PermissionSetCreate,
    RoleAssignment,
    TileCreate,
    TilePermissions,
    TileUpdate,
)
from mere.exceptions import HTTPError
from mere.models import (
    DashboardTile,
    DashboardTilePermission,
    Permission,
    Role,
    WorkspacePermissionDelegation,
    WorkspacePermissionSet,
    WorkspaceRoleAssignment,
)
from mere.rbac import CedarEntity, CedarReference
from mere.tenancy import TenantContext, TenantScope


class InMemoryTable:
    """Very small in-memory stand-in for :mod:`mere.orm` model managers."""

    def __init__(self, model_type: type[Any]) -> None:
        self._model_type = model_type
        self._storage: dict[str | None, list[Any]] = defaultdict(list)

    def _bucket_key(self, tenant: TenantContext | None) -> str | None:
        if tenant is None:
            return None
        return tenant.key()

    def _matches(self, record: Any, filters: dict[str, object] | None) -> bool:
        if not filters:
            return True
        for field, expected in filters.items():
            if getattr(record, field) != expected:
                return False
        return True

    async def create(self, data: Any, *, tenant: TenantContext | None = None) -> Any:
        record = data if isinstance(data, self._model_type) else self._model_type(**data)
        self._storage[self._bucket_key(tenant)].append(record)
        return record

    async def get(
        self,
        *,
        tenant: TenantContext | None = None,
        filters: dict[str, object] | None = None,
    ) -> Any | None:
        bucket = list(self._storage.get(self._bucket_key(tenant), ()))
        for record in reversed(bucket):
            if self._matches(record, filters):
                return record
        return None

    async def list(
        self,
        *,
        tenant: TenantContext | None = None,
        filters: dict[str, object] | None = None,
        order_by: Iterable[str] | None = None,
        limit: int | None = None,
    ) -> list[Any]:
        bucket = [
            record for record in self._storage.get(self._bucket_key(tenant), ()) if self._matches(record, filters)
        ]
        if order_by:
            field, *rest = next(iter(order_by)).split()
            reverse = any(part.lower() == "desc" for part in rest)
            bucket.sort(key=lambda item: getattr(item, field), reverse=reverse)
        if limit is not None:
            bucket = bucket[:limit]
        return list(bucket)

    async def update(
        self,
        values: dict[str, object],
        *,
        tenant: TenantContext | None = None,
        filters: dict[str, object] | None = None,
    ) -> list[Any]:
        bucket_key = self._bucket_key(tenant)
        bucket = self._storage.get(bucket_key, [])
        updated: list[Any] = []
        new_bucket: list[Any] = []
        for record in bucket:
            if self._matches(record, filters):
                data = structs.asdict(record)
                data.update(values)
                new_record = self._model_type(**data)
                updated.append(new_record)
                new_bucket.append(new_record)
            else:
                new_bucket.append(record)
        self._storage[bucket_key] = new_bucket
        return updated

    async def delete(
        self,
        *,
        tenant: TenantContext | None = None,
        filters: dict[str, object] | None = None,
    ) -> int:
        bucket_key = self._bucket_key(tenant)
        bucket = self._storage.get(bucket_key, [])
        kept: list[Any] = []
        removed = 0
        for record in bucket:
            if self._matches(record, filters):
                removed += 1
            else:
                kept.append(record)
        self._storage[bucket_key] = kept
        return removed


class _Namespace:
    def __init__(self, managers: dict[str, InMemoryTable]) -> None:
        for name, manager in managers.items():
            setattr(self, name, manager)


class FakeORM:
    def __init__(self, *, tenants: dict[str, InMemoryTable], admin: dict[str, InMemoryTable]) -> None:
        self.tenants = _Namespace(tenants)
        self.admin = _Namespace(admin)


class AuditRow(Struct, kw_only=True, omit_defaults=True):
    id: str
    created_at: dt.datetime
    actor_id: str | None
    actor_type: str | None
    action: str
    entity_type: str
    entity_id: str | None = None
    metadata: dict[str, Any] = {}


class TickingClock:
    def __init__(self, initial: dt.datetime) -> None:
        self.value = initial

    def now(self) -> dt.datetime:
        return self.value


@pytest.fixture
def tenant_alpha() -> TenantContext:
    return TenantContext(tenant="alpha", site="demo", domain="local.test", scope=TenantScope.TENANT)


@pytest.fixture
def tenant_beta() -> TenantContext:
    return TenantContext(tenant="beta", site="demo", domain="local.test", scope=TenantScope.TENANT)


@pytest.fixture
def admin_ctx() -> TenantContext:
    return TenantContext(tenant="admin", site="demo", domain="local.test", scope=TenantScope.ADMIN)


@pytest.mark.asyncio
async def test_tile_service_crud_cycle_covers_admin_and_tenant_scopes(
    admin_ctx: TenantContext, tenant_alpha: TenantContext
) -> None:
    tiles = InMemoryTable(DashboardTile)
    permissions = InMemoryTable(DashboardTilePermission)
    orm = FakeORM(tenants={"dashboard_tiles": tiles, "dashboard_tile_permissions": permissions}, admin={})
    service = BootstrapTileService(orm)  # type: ignore[arg-type]

    payload = TileCreate(
        title="Revenue",
        layout={"kind": "chart"},
        description=None,
        data_sources=("warehouse",),
        ai_insights_enabled=True,
    )
    record = await service.create_tile(
        tenant=admin_ctx,
        workspace_id=tenant_alpha.tenant,
        principal=None,
        payload=payload,
    )
    assert record.workspace_id == tenant_alpha.tenant
    assert record.ai_insights_enabled is True

    unchanged = await service.update_tile(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        tile_id=record.id,
        principal=None,
        payload=TileUpdate(),
    )
    assert unchanged.id == record.id

    enriched = await service.update_tile(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        tile_id=record.id,
        principal=None,
        payload=TileUpdate(
            description="Revenue insights",
            data_sources=("warehouse", "ml"),
            ai_insights_enabled=True,
        ),
    )
    assert enriched.data_sources == ("warehouse", "ml")

    await service.set_permissions(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        tile_id=record.id,
        principal=None,
        permissions=TilePermissions(roles=("analyst",), users=("user-1",)),
    )
    updated_perms = await service.set_permissions(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        tile_id=record.id,
        principal=None,
        permissions=TilePermissions(roles=("analyst", "ops"), users=("user-2",)),
    )
    assert updated_perms.roles == ("analyst", "ops")

    toggled = await service.toggle_ai_insights(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        tile_id=record.id,
        principal=None,
        enabled=False,
    )
    assert toggled.ai_insights_enabled is False

    refreshed = await service.update_tile(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        tile_id=record.id,
        principal=None,
        payload=TileUpdate(title="Daily Revenue", layout={"kind": "table"}),
    )
    assert refreshed.title == "Daily Revenue"

    await service.delete_tile(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        tile_id=record.id,
        principal=None,
    )
    assert await tiles.get(tenant=tenant_alpha, filters={"id": record.id}) is None
    assert await permissions.list(tenant=tenant_alpha) == []

    with pytest.raises(HTTPError) as missing_delete:
        await service.delete_tile(
            tenant=tenant_alpha,
            workspace_id=tenant_alpha.tenant,
            tile_id=record.id,
            principal=None,
        )
    assert isinstance(missing_delete.value, HTTPError)
    assert missing_delete.value.detail["detail"] == "tile_missing"

    with pytest.raises(HTTPError) as missing_tile:
        await service.update_tile(
            tenant=tenant_alpha,
            workspace_id=tenant_alpha.tenant,
            tile_id=record.id,
            principal=None,
            payload=TileUpdate(title="fail"),
        )
    assert isinstance(missing_tile.value, HTTPError)
    assert missing_tile.value.detail["detail"] == "tile_missing"

    with pytest.raises(HTTPError) as missing_load:
        await service.update_tile(
            tenant=tenant_alpha,
            workspace_id=tenant_alpha.tenant,
            tile_id=record.id,
            principal=None,
            payload=TileUpdate(),
        )
    assert isinstance(missing_load.value, HTTPError)
    assert missing_load.value.detail["detail"] == "tile_missing"

    with pytest.raises(HTTPError) as missing_toggle:
        await service.toggle_ai_insights(
            tenant=tenant_alpha,
            workspace_id=tenant_alpha.tenant,
            tile_id=record.id,
            principal=None,
            enabled=True,
        )
    assert isinstance(missing_toggle.value, HTTPError)
    assert missing_toggle.value.detail["detail"] == "tile_missing"


@pytest.mark.asyncio
async def test_tile_service_list_and_get_include_permissions(
    tenant_alpha: TenantContext,
) -> None:
    tiles = InMemoryTable(DashboardTile)
    permissions = InMemoryTable(DashboardTilePermission)
    orm = FakeORM(tenants={"dashboard_tiles": tiles, "dashboard_tile_permissions": permissions}, admin={})
    service = BootstrapTileService(orm)  # type: ignore[arg-type]

    record = DashboardTile(
        workspace_id=tenant_alpha.tenant,
        title="Ops Overview",
        layout={"kind": "chart"},
    )
    created = await tiles.create(record, tenant=tenant_alpha)
    await permissions.create(
        DashboardTilePermission(tile_id=created.id, roles=("analyst",), users=()),
        tenant=tenant_alpha,
    )

    listing = await service.list_tiles(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        principal=None,
    )
    assert len(listing) == 1
    assert listing[0].permissions is not None
    fetched = await service.get_tile(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        tile_id=created.id,
        principal=None,
    )
    assert fetched.id == created.id


@pytest.mark.asyncio
async def test_rbac_service_creates_roles_and_assigns_users(
    admin_ctx: TenantContext, tenant_alpha: TenantContext
) -> None:
    permission_sets = InMemoryTable(WorkspacePermissionSet)
    role_assignments = InMemoryTable(WorkspaceRoleAssignment)
    roles = InMemoryTable(Role)
    permissions = InMemoryTable(Permission)
    orm = FakeORM(
        tenants={
            "workspace_permission_sets": permission_sets,
            "workspace_role_assignments": role_assignments,
        },
        admin={"roles": roles, "permissions": permissions},
    )
    service = BootstrapRbacService(orm)  # type: ignore[arg-type]

    created = await service.create_permission_set(
        tenant=admin_ctx,
        workspace_id=tenant_alpha.tenant,
        principal=None,
        payload=PermissionSetCreate(name="ops", permissions=("tiles:view", "tiles:view", "tiles:edit")),
    )
    assert created.permissions == ("tiles:view", "tiles:edit")
    assert await roles.get(tenant=None, filters={"id": created.role_id}) is not None
    assert len(await permissions.list(tenant=None, filters={"role_id": created.role_id})) == 2

    with pytest.raises(HTTPError) as duplicate:
        await service.create_permission_set(
            tenant=tenant_alpha,
            workspace_id=tenant_alpha.tenant,
            principal=None,
            payload=PermissionSetCreate(name="ops", permissions=("tiles:view",)),
        )
    assert isinstance(duplicate.value, HTTPError)
    assert duplicate.value.status == 409

    assigned = await service.assign_role(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        role_id=created.role_id,
        principal=None,
        payload=RoleAssignment(user_ids=("u1", "u2")),
    )
    assert assigned.assigned_user_ids == ("u1", "u2")

    again = await service.assign_role(
        tenant=tenant_alpha,
        workspace_id=tenant_alpha.tenant,
        role_id=created.role_id,
        principal=None,
        payload=RoleAssignment(user_ids=("u1", "u3")),
    )
    assert again.assigned_user_ids == ("u1", "u3")
    assert len(await role_assignments.list(tenant=tenant_alpha)) == 3

    with pytest.raises(HTTPError) as missing_set:
        await service.assign_role(
            tenant=tenant_alpha,
            workspace_id=tenant_alpha.tenant,
            role_id="missing",
            principal=None,
            payload=RoleAssignment(user_ids=("u5",)),
        )
    assert isinstance(missing_set.value, HTTPError)
    assert missing_set.value.detail["detail"] == "permission_set_missing"


@pytest.mark.asyncio
async def test_delegation_service_grant_merge_revoke_and_resolution(
    tenant_alpha: TenantContext, tenant_beta: TenantContext, admin_ctx: TenantContext
) -> None:
    delegations = InMemoryTable(WorkspacePermissionDelegation)
    permission_sets = InMemoryTable(WorkspacePermissionSet)
    assignments = InMemoryTable(WorkspaceRoleAssignment)
    orm = FakeORM(
        tenants={
            "permission_delegations": delegations,
            "workspace_permission_sets": permission_sets,
            "workspace_role_assignments": assignments,
        },
        admin={},
    )
    clock = TickingClock(dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc))
    service = BootstrapDelegationService(orm, clock=clock.now)  # type: ignore[arg-type]
    grantor_principal = CedarEntity(type="User", id="grantor")

    with pytest.raises(HTTPError) as window_error:
        await service.grant(
            tenant=tenant_alpha,
            principal=grantor_principal,
            payload=DelegationGrant(
                from_user_id="grantor",
                to_user_id="delegate",
                scopes=("tiles:view",),
                workspace_id=tenant_alpha.tenant,
                starts_at=clock.now(),
                ends_at=clock.now(),
            ),
        )
    assert isinstance(window_error.value, HTTPError)
    assert window_error.value.detail["detail"] == "invalid_window"

    await permission_sets.create(
        WorkspacePermissionSet(
            workspace_id=tenant_alpha.tenant,
            name="ops",
            permissions=("tiles:view", "tiles:edit"),
            role_id="role-ops",
        ),
        tenant=tenant_alpha,
    )
    await assignments.create(
        WorkspaceRoleAssignment(
            workspace_id=tenant_alpha.tenant,
            role_id="role-ops",
            user_id="grantor",
            assigned_at=clock.now(),
        ),
        tenant=tenant_alpha,
    )

    await delegations.create(
        WorkspacePermissionDelegation(
            workspace_id=tenant_alpha.tenant,
            from_user_id="grantor",
            to_user_id="delegate",
            scopes=("tiles:view",),
            starts_at=clock.now() - dt.timedelta(days=3),
            ends_at=clock.now() - dt.timedelta(days=2),
        ),
        tenant=tenant_alpha,
    )
    await assignments.create(
        WorkspaceRoleAssignment(
            workspace_id=tenant_alpha.tenant,
            role_id="ghost",
            user_id="delegate",
            assigned_at=clock.now(),
        ),
        tenant=tenant_alpha,
    )

    with pytest.raises(HTTPError) as scope_error:
        await service.grant(
            tenant=tenant_alpha,
            principal=grantor_principal,
            payload=DelegationGrant(
                from_user_id="grantor",
                to_user_id="delegate",
                scopes=("tiles:manage",),
                workspace_id=tenant_alpha.tenant,
                starts_at=clock.now(),
                ends_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
    assert isinstance(scope_error.value, HTTPError)
    assert scope_error.value.detail["detail"] == "scope_not_granted"

    start = clock.now() - dt.timedelta(hours=1)
    end = clock.now() + dt.timedelta(hours=1)
    first = await service.grant(
        tenant=tenant_alpha,
        principal=grantor_principal,
        payload=DelegationGrant(
            from_user_id="grantor",
            to_user_id="delegate",
            scopes=("tiles:view",),
            workspace_id=tenant_alpha.tenant,
            starts_at=start,
            ends_at=end,
        ),
    )
    assert first.scopes == ("tiles:view",)

    extended = await service.grant(
        tenant=tenant_alpha,
        principal=grantor_principal,
        payload=DelegationGrant(
            from_user_id="grantor",
            to_user_id="delegate",
            scopes=("tiles:edit",),
            workspace_id=tenant_alpha.tenant,
            starts_at=clock.now(),
            ends_at=clock.now() + dt.timedelta(hours=2),
        ),
    )
    assert extended.scopes == ("tiles:edit", "tiles:view")

    active = await service.list_active(
        tenant=tenant_alpha,
        principal=None,
        user_id="delegate",
    )
    assert active[0].scopes == extended.scopes

    active_ws = await service.list_active(
        tenant=tenant_alpha,
        principal=None,
        user_id="delegate",
        workspace_id=tenant_alpha.tenant,
    )
    assert active_ws[0].workspace_id == tenant_alpha.tenant

    with pytest.raises(HTTPError) as forbidden_list:
        await service.list_active(
            tenant=admin_ctx,
            principal=None,
        )
    assert isinstance(forbidden_list.value, HTTPError)
    assert forbidden_list.value.detail["detail"] == "tenant_required"

    permissions_for_delegate = await service.resolve_effective_permissions(
        tenant=tenant_alpha,
        principal=None,
        user_id="delegate",
        workspace_id=tenant_alpha.tenant,
    )
    assert permissions_for_delegate == ("tiles:edit", "tiles:view")

    await delegations.create(
        WorkspacePermissionDelegation(
            workspace_id=tenant_beta.tenant,
            from_user_id="grantor",
            to_user_id="delegate",
            scopes=("tiles:view",),
            starts_at=start,
            ends_at=end,
        ),
        tenant=tenant_beta,
    )
    await delegations.create(
        WorkspacePermissionDelegation(
            workspace_id="other",
            from_user_id="grantor",
            to_user_id="delegate",
            scopes=("tiles:view",),
            starts_at=start,
            ends_at=end,
        ),
        tenant=tenant_alpha,
    )
    filtered_scopes = await service.resolve_effective_permissions(
        tenant=tenant_alpha,
        principal=None,
        user_id="delegate",
        workspace_id=tenant_alpha.tenant,
    )
    assert filtered_scopes == ("tiles:edit", "tiles:view")
    cross_workspace = await service.resolve_effective_permissions(
        tenant=tenant_alpha,
        principal=None,
        user_id="delegate",
    )
    assert cross_workspace == ("tiles:edit", "tiles:view")

    with pytest.raises(HTTPError) as forbidden_resolve:
        await service.resolve_effective_permissions(
            tenant=admin_ctx,
            principal=None,
            user_id="delegate",
        )
    assert isinstance(forbidden_resolve.value, HTTPError)
    assert forbidden_resolve.value.detail["detail"] == "tenant_required"

    with pytest.raises(HTTPError) as forbidden_revoke:
        await service.revoke(
            tenant=admin_ctx,
            principal=None,
            delegation_id=first.id,
        )
    assert isinstance(forbidden_revoke.value, HTTPError)
    assert forbidden_revoke.value.detail["detail"] == "tenant_required"

    clock.value = clock.now() + dt.timedelta(hours=3)
    await service.revoke(
        tenant=tenant_alpha,
        principal=grantor_principal,
        delegation_id=first.id,
    )

    clock.value = clock.now() + dt.timedelta(seconds=1)
    now_empty = await service.list_active(
        tenant=tenant_alpha,
        principal=None,
        user_id="delegate",
        workspace_id=tenant_alpha.tenant,
    )
    assert now_empty == ()

    with pytest.raises(HTTPError) as missing_delegate:
        await service.revoke(
            tenant=tenant_alpha,
            principal=grantor_principal,
            delegation_id="missing",
        )
    assert isinstance(missing_delegate.value, HTTPError)
    assert missing_delegate.value.detail["detail"] == "delegation_missing"


@pytest.mark.asyncio
async def test_delegation_service_enforces_actor_authorization(
    tenant_alpha: TenantContext,
    admin_ctx: TenantContext,
) -> None:
    delegations = InMemoryTable(WorkspacePermissionDelegation)
    permission_sets = InMemoryTable(WorkspacePermissionSet)
    assignments = InMemoryTable(WorkspaceRoleAssignment)
    orm = FakeORM(
        tenants={
            "permission_delegations": delegations,
            "workspace_permission_sets": permission_sets,
            "workspace_role_assignments": assignments,
        },
        admin={},
    )
    clock = TickingClock(dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc))
    service = BootstrapDelegationService(orm, clock=clock.now)  # type: ignore[arg-type]

    await permission_sets.create(
        WorkspacePermissionSet(
            workspace_id=tenant_alpha.tenant,
            name="ops",
            permissions=("tiles:view",),
            role_id="role-ops",
        ),
        tenant=tenant_alpha,
    )
    await assignments.create(
        WorkspaceRoleAssignment(
            workspace_id=tenant_alpha.tenant,
            role_id="role-ops",
            user_id="grantor",
            assigned_at=clock.now(),
        ),
        tenant=tenant_alpha,
    )

    def make_payload() -> DelegationGrant:
        start = clock.now()
        return DelegationGrant(
            from_user_id="grantor",
            to_user_id="delegate",
            scopes=("tiles:view",),
            workspace_id=tenant_alpha.tenant,
            starts_at=start,
            ends_at=start + dt.timedelta(hours=1),
        )

    intruder = CedarEntity(type="User", id="intruder")
    with pytest.raises(HTTPError) as unauthorized_grant:
        await service.grant(
            tenant=tenant_alpha,
            principal=intruder,
            payload=make_payload(),
        )
    unauthorized_grant_error = cast(HTTPError, unauthorized_grant.value)
    assert unauthorized_grant_error.detail["detail"] == "delegation_forbidden"

    with pytest.raises(HTTPError) as wrong_scope:
        await service.grant(
            tenant=admin_ctx,
            principal=CedarEntity(type="User", id="grantor"),
            payload=make_payload(),
        )
    wrong_scope_error = cast(HTTPError, wrong_scope.value)
    assert wrong_scope_error.detail["detail"] == "tenant_required"

    grantor = CedarEntity(type="User", id="grantor")
    granted = await service.grant(
        tenant=tenant_alpha,
        principal=grantor,
        payload=make_payload(),
    )

    with pytest.raises(HTTPError) as unauthorized_revoke:
        await service.revoke(
            tenant=tenant_alpha,
            principal=intruder,
            delegation_id=granted.id,
        )
    unauthorized_revoke_error = cast(HTTPError, unauthorized_revoke.value)
    assert unauthorized_revoke_error.detail["detail"] == "delegation_forbidden"

    delegate = CedarEntity(type="User", id="delegate")
    await service.revoke(
        tenant=tenant_alpha,
        principal=delegate,
        delegation_id=granted.id,
    )

    with pytest.raises(HTTPError) as admin_scope_revoke:
        await service.revoke(
            tenant=admin_ctx,
            principal=delegate,
            delegation_id=granted.id,
        )
    admin_scope_revoke_error = cast(HTTPError, admin_scope_revoke.value)
    assert admin_scope_revoke_error.detail["detail"] == "tenant_required"

    clock.value = clock.now() + dt.timedelta(hours=2)
    admin = CedarEntity(type="AdminUser", id="admin", attributes={"tenant": tenant_alpha.tenant})
    await service.grant(
        tenant=tenant_alpha,
        principal=admin,
        payload=make_payload(),
    )


@pytest.mark.asyncio
async def test_audit_service_filters_and_exports(admin_ctx: TenantContext, tenant_alpha: TenantContext) -> None:
    audit_log = InMemoryTable(AuditRow)
    orm = FakeORM(tenants={"audit_log": audit_log}, admin={})
    service = BootstrapAuditService(orm)  # type: ignore[arg-type]

    base = dt.datetime(2024, 5, 1, tzinfo=dt.timezone.utc)
    await audit_log.create(
        AuditRow(
            id="evt-1",
            created_at=base - dt.timedelta(days=1),
            actor_id="user-1",
            actor_type="user",
            action="tile.created",
            entity_type="tile",
            entity_id="tile-1",
            metadata={"shape": "chart"},
        ),
        tenant=tenant_alpha,
    )
    await audit_log.create(
        AuditRow(
            id="evt-2",
            created_at=base,
            actor_id="sa-1",
            actor_type="sysadmin",
            action="tile.deleted",
            entity_type="tile",
            entity_id="tile-2",
            metadata={},
        ),
        tenant=tenant_alpha,
    )
    await audit_log.create(
        AuditRow(
            id="evt-3",
            created_at=base + dt.timedelta(days=1),
            actor_id="user-2",
            actor_type="user",
            action="workspace.updated",
            entity_type="workspace",
            entity_id=None,
            metadata={},
        ),
        tenant=tenant_alpha,
    )

    page = await service.read(
        tenant=admin_ctx,
        workspace_id=tenant_alpha.tenant,
        principal=None,
        actor="sa-1",
        action="tile.deleted",
        entity="tile",
        from_time=base - dt.timedelta(hours=1),
        to_time=base + dt.timedelta(hours=1),
    )
    assert len(page.entries) == 1
    assert page.entries[0].actor.endswith("sysadmin")

    csv_export = await service.export(
        tenant=admin_ctx,
        workspace_id=tenant_alpha.tenant,
        principal=None,
        query=AuditLogExportQuery(format="csv"),
        action="tile.deleted",
    )
    assert csv_export.content_type == "text/csv"
    assert csv_export.filename == f"audit-{tenant_alpha.tenant}.csv"

    json_export = await service.export(
        tenant=admin_ctx,
        workspace_id=tenant_alpha.tenant,
        principal=None,
        query=AuditLogExportQuery(format="json"),
        actor=None,
    )
    assert json_export.content_type == "application/json"

    workspace_page = await service.read(
        tenant=admin_ctx,
        workspace_id=tenant_alpha.tenant,
        principal=None,
        actor=None,
        action=None,
        entity="workspace",
    )
    assert len(workspace_page.entries) == 1

    recent_page = await service.read(
        tenant=admin_ctx,
        workspace_id=tenant_alpha.tenant,
        principal=None,
        actor=None,
        action=None,
        from_time=base,
    )
    assert all(entry.timestamp >= base for entry in recent_page.entries)

    bounded_page = await service.read(
        tenant=admin_ctx,
        workspace_id=tenant_alpha.tenant,
        principal=None,
        actor=None,
        action=None,
        to_time=base,
    )
    assert all(entry.timestamp <= base for entry in bounded_page.entries)


@pytest.mark.asyncio
async def test_build_cedar_engine_includes_assignments_and_delegations(
    tenant_alpha: TenantContext, admin_ctx: TenantContext
) -> None:
    permission_sets = InMemoryTable(WorkspacePermissionSet)
    assignments = InMemoryTable(WorkspaceRoleAssignment)
    delegations = InMemoryTable(WorkspacePermissionDelegation)
    orm = FakeORM(
        tenants={
            "workspace_permission_sets": permission_sets,
            "workspace_role_assignments": assignments,
            "permission_delegations": delegations,
        },
        admin={},
    )
    await permission_sets.create(
        WorkspacePermissionSet(
            workspace_id=tenant_alpha.tenant,
            name="ops",
            permissions=("tiles:view", "tiles:edit"),
            role_id="role-ops",
        ),
        tenant=tenant_alpha,
    )
    now = dt.datetime(2024, 5, 1, tzinfo=dt.timezone.utc)
    await assignments.create(
        WorkspaceRoleAssignment(
            workspace_id=tenant_alpha.tenant,
            role_id="role-ops",
            user_id="analyst",
            assigned_at=now,
        ),
        tenant=tenant_alpha,
    )
    await assignments.create(
        WorkspaceRoleAssignment(
            workspace_id=tenant_alpha.tenant,
            role_id="ghost-role",
            user_id="bystander",
            assigned_at=now,
        ),
        tenant=tenant_alpha,
    )
    await delegations.create(
        WorkspacePermissionDelegation(
            workspace_id=tenant_alpha.tenant,
            from_user_id="analyst",
            to_user_id="delegate",
            scopes=("tiles:view",),
            starts_at=now - dt.timedelta(days=1),
            ends_at=now + dt.timedelta(days=1),
        ),
        tenant=tenant_alpha,
    )
    await delegations.create(
        WorkspacePermissionDelegation(
            workspace_id=tenant_alpha.tenant,
            from_user_id="analyst",
            to_user_id="delegate",
            scopes=("tiles:edit",),
            starts_at=now - dt.timedelta(days=3),
            ends_at=now - dt.timedelta(days=2),
        ),
        tenant=tenant_alpha,
    )

    engine = await build_cedar_engine(orm, tenant=tenant_alpha, at=now)  # type: ignore[arg-type]
    policies = list(engine.policies())
    assert len(policies) == 3
    assert any(
        policy.principal == CedarReference("User", "delegate") and "tiles:view" in policy.actions for policy in policies
    )
    analyst = CedarEntity(type="User", id="analyst")
    resource = CedarEntity(type="workspace", id=tenant_alpha.tenant)
    assert engine.check(principal=analyst, action="tiles:edit", resource=resource)

    with pytest.raises(HTTPError) as forbidden:
        await build_cedar_engine(orm, tenant=admin_ctx, at=now)  # type: ignore[arg-type]
    assert isinstance(forbidden.value, HTTPError)
    assert forbidden.value.detail["detail"] == "tenant_required"
