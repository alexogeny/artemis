import datetime as dt

import artemis.rbac as rbac_module
from artemis.id57 import generate_id57
from artemis.models import (
    AdminRoleAssignment,
    Permission,
    PermissionEffect,
    Role,
    RoleScope,
    UserRole,
)
from artemis.rbac import (
    CedarEffect,
    CedarEngine,
    CedarEntity,
    CedarPolicy,
    CedarReference,
    RoleBinding,
    bindings_from_admin,
    bindings_from_users,
    build_engine,
)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def test_cedar_reference_matching() -> None:
    entity = CedarEntity(type="User", id="abc", attributes={"tenant": "acme"})
    assert entity.attribute("tenant") == "acme"
    assert entity.attribute("missing") is None
    assert CedarReference("User").matches(entity)
    assert CedarReference("User", "abc").matches(entity)
    assert not CedarReference("AdminUser", "abc").matches(entity)
    assert CedarReference("*", "*").matches(entity)


def test_admin_rbac_policies_allow_and_deny() -> None:
    now = _now()
    role_id = generate_id57()
    admin_user = generate_id57()
    role = Role(
        id=role_id,
        name="admin-billing",
        scope=RoleScope.ADMIN,
        tenant=None,
        description=None,
        created_at=now,
        updated_at=now,
    )
    allow_permission = Permission(
        id=generate_id57(),
        role_id=role_id,
        action="billing:read",
        resource_type="billing",
        effect=PermissionEffect.ALLOW,
        condition={"context_equals": {"tenant": "acme"}},
        created_at=now,
        updated_at=now,
    )
    deny_permission = Permission(
        id=generate_id57(),
        role_id=role_id,
        action="billing:read",
        resource_type="billing",
        effect=PermissionEffect.DENY,
        condition={"principal_attr_equals": {"tenant": "acme"}},
        created_at=now,
        updated_at=now,
    )
    assignment = AdminRoleAssignment(
        id=generate_id57(),
        admin_user_id=admin_user,
        role_id=role_id,
        assigned_at=now,
    )

    engine = build_engine(
        roles=[role],
        permissions=[allow_permission, deny_permission],
        bindings=bindings_from_admin([assignment]),
    )
    principal = CedarEntity(type="AdminUser", id=str(admin_user), attributes={"tenant": "acme"})
    resource = CedarEntity(type="billing", id="acme")

    assert (
        engine.check(
            principal=principal,
            action="billing:read",
            resource=resource,
            context={"tenant": "acme"},
        )
        is False
    )
    assert (
        engine.check(
            principal=principal,
            action="billing:read",
            resource=resource,
            context={"tenant": "beta"},
        )
        is False
    )

    engine = build_engine(
        roles=[role],
        permissions=[allow_permission],
        bindings=bindings_from_admin([assignment]),
    )
    assert (
        engine.check(
            principal=principal,
            action="billing:read",
            resource=resource,
            context={"tenant": "acme"},
        )
        is True
    )
    assert (
        engine.check(
            principal=principal,
            action="billing:read",
            resource=resource,
            context={"tenant": "beta"},
        )
        is False
    )

    policies = engine.policies()
    assert policies[0].resource.identifier == "*"


def test_tenant_user_bindings_scope_resources() -> None:
    now = _now()
    tenant = "acme"
    role_id = generate_id57()
    user_id = generate_id57()
    role = Role(
        id=role_id,
        name="order-writer",
        scope=RoleScope.TENANT,
        tenant=tenant,
        description=None,
        created_at=now,
        updated_at=now,
    )
    permission = Permission(
        id=generate_id57(),
        role_id=role_id,
        action="orders:write, orders:approve",
        resource_type="orders",
        effect=PermissionEffect.ALLOW,
        condition={},
        created_at=now,
        updated_at=now,
    )
    binding = UserRole(
        id=generate_id57(),
        user_id=user_id,
        role_id=role_id,
        assigned_at=now,
    )

    engine = build_engine(
        roles=[role],
        permissions=[permission],
        bindings=bindings_from_users([binding]),
    )

    principal = CedarEntity(type="User", id=str(user_id))
    resource = CedarEntity(type="orders", id="acme")
    assert engine.check(principal=principal, action="orders:write", resource=resource, context=None)
    assert engine.check(principal=principal, action="orders:approve", resource=resource, context=None)
    other_resource = CedarEntity(type="orders", id="beta")
    assert engine.check(principal=principal, action="orders:write", resource=other_resource, context=None) is False

    policy_actions = engine.policies()[0].actions
    assert policy_actions == ("orders:write", "orders:approve")


def test_build_engine_skips_unknown_roles() -> None:
    now = _now()
    role = Role(
        id=generate_id57(),
        name="unused",
        scope=RoleScope.ADMIN,
        tenant=None,
        description=None,
        created_at=now,
        updated_at=now,
    )
    permission = Permission(
        id=generate_id57(),
        role_id=generate_id57(),
        action="noop",
        resource_type="billing",
        effect=PermissionEffect.ALLOW,
        condition={},
        created_at=now,
        updated_at=now,
    )
    binding = AdminRoleAssignment(
        id=generate_id57(),
        admin_user_id=generate_id57(),
        role_id=generate_id57(),
        assigned_at=now,
    )
    engine = build_engine(
        roles=[role],
        permissions=[permission],
        bindings=bindings_from_admin([binding]),
    )
    assert engine.policies() == ()


def test_cedar_policy_matching_branches() -> None:
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "123"),
        actions=("read",),
        resource=CedarReference("doc", "abc"),
        condition=lambda principal, action, resource, context: False,
    )
    principal = CedarEntity(type="User", id="123")
    resource = CedarEntity(type="doc", id="abc")
    assert policy.matches(CedarEntity(type="AdminUser", id="123"), "read", resource, None) is False
    assert policy.matches(principal, "write", resource, None) is False
    assert policy.matches(principal, "read", CedarEntity(type="doc", id="xyz"), None) is False
    assert policy.matches(principal, "read", resource, None) is False


def test_condition_requires_matching_principal_attributes() -> None:
    now = _now()
    role_id = generate_id57()
    admin_user = generate_id57()
    role = Role(
        id=role_id,
        name="attribute-check",
        scope=RoleScope.ADMIN,
        tenant=None,
        description=None,
        created_at=now,
        updated_at=now,
    )
    permission = Permission(
        id=generate_id57(),
        role_id=role_id,
        action="reports:view",
        resource_type="reports",
        effect=PermissionEffect.ALLOW,
        condition={"principal_attr_equals": {"tier": "gold"}},
        created_at=now,
        updated_at=now,
    )
    binding = AdminRoleAssignment(
        id=generate_id57(),
        admin_user_id=admin_user,
        role_id=role_id,
        assigned_at=now,
    )
    engine = build_engine(
        roles=[role],
        permissions=[permission],
        bindings=bindings_from_admin([binding]),
    )
    principal = CedarEntity(type="AdminUser", id=str(admin_user), attributes={"tier": "silver"})
    resource = CedarEntity(type="reports", id="*")
    assert engine.check(principal=principal, action="reports:view", resource=resource, context=None) is False
    upgraded = CedarEntity(type="AdminUser", id=str(admin_user), attributes={"tier": "gold"})
    assert engine.check(principal=upgraded, action="reports:view", resource=resource, context=None) is True


def test_permission_resource_for_tenant_target() -> None:
    now = _now()
    role_id = generate_id57()
    tenant_role = Role(
        id=role_id,
        name="tenant-specific",
        scope=RoleScope.TENANT,
        tenant="acme",
        description=None,
        created_at=now,
        updated_at=now,
    )
    permission = Permission(
        id=generate_id57(),
        role_id=role_id,
        action="docs:edit",
        resource_type="docs",
        effect=PermissionEffect.ALLOW,
        condition={"tenant": "beta"},
        created_at=now,
        updated_at=now,
    )
    binding = UserRole(id=generate_id57(), user_id=generate_id57(), role_id=role_id, assigned_at=now)
    engine = build_engine(
        roles=[tenant_role],
        permissions=[permission],
        bindings=bindings_from_users([binding]),
    )
    policy = engine.policies()[0]
    assert policy.resource.identifier == "beta"


def test_to_effect_accepts_strings() -> None:
    assert rbac_module._to_effect("ALLOW") is CedarEffect.ALLOW
    assert rbac_module._to_effect("deny") is CedarEffect.DENY


def test_cedar_engine_uses_index_for_matches() -> None:
    principal = CedarEntity(type="User", id="user-1", attributes=None)
    resource = CedarEntity(type="orders", id="acme", attributes=None)
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "user-1"),
        actions=("orders:read",),
        resource=CedarReference("orders", "acme"),
    )

    class FailingReference(CedarReference):
        def __init__(self) -> None:
            object.__setattr__(self, "entity_type", "Other")
            object.__setattr__(self, "identifier", "sentinel")

        def matches(
            self,
            entity: CedarEntity,
        ) -> bool:
            raise AssertionError("Sentinel policy should not be evaluated")

    sentinel = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=FailingReference(),
        actions=("noop",),
        resource=CedarReference("orders", "*"),
    )

    engine = CedarEngine([policy, sentinel])
    assert engine.check(principal=principal, action="orders:read", resource=resource, context=None) is True


def test_build_engine_indexes_permissions_once() -> None:
    now = _now()
    role_id = generate_id57()
    role = Role(
        id=role_id,
        name="reader",
        scope=RoleScope.TENANT,
        tenant="acme",
        description=None,
        created_at=now,
        updated_at=now,
    )
    permission = Permission(
        id=generate_id57(),
        role_id=role_id,
        action="orders:read",
        resource_type="orders",
        effect=PermissionEffect.ALLOW,
        condition={},
        created_at=now,
        updated_at=now,
    )

    class CountingPermissions:
        def __init__(self, data: list[Permission]) -> None:
            self.data = data
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            return iter(self.data)

    permissions = CountingPermissions([permission])
    bindings = [RoleBinding(principal_type="User", principal_id="user-1", role_id=role_id)]
    engine = build_engine(roles=[role], permissions=permissions, bindings=bindings)
    assert isinstance(engine, CedarEngine)
    assert permissions.iterations == 1


def test_cedar_engine_supports_wildcard_principals_and_actions() -> None:
    wildcard_policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("*", "*"),
        actions=(),
        resource=CedarReference("orders", "*"),
    )
    engine = CedarEngine([wildcard_policy])
    principal = CedarEntity(type="User", id="random")
    resource = CedarEntity(type="orders", id="acme")
    assert engine.check(principal=principal, action="orders:delete", resource=resource, context=None) is True


def test_cedar_engine_deduplicates_candidates() -> None:
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "user-1"),
        actions=("orders:read",),
        resource=CedarReference("orders", "*"),
    )
    engine = CedarEngine([policy, policy])
    principal = CedarEntity(type="User", id="user-1")
    resource = CedarEntity(type="orders", id="beta")
    assert engine.check(principal=principal, action="orders:read", resource=resource, context=None) is True


def test_policy_action_keys_normalizes_wildcards() -> None:
    keys = rbac_module._policy_action_keys(["orders:read", "*", "orders:read"])
    assert keys == ("orders:read", None)
