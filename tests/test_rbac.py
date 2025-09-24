import datetime as dt
import json

import pytest

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
    _condition_from_mapping,
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


def test_build_engine_prefers_cedarpy_backend() -> None:
    now = _now()
    role_id = generate_id57()
    admin_user = generate_id57()
    role = Role(
        id=role_id,
        name="admin-reporting",
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
        condition={"context_equals": {"tenant": "acme"}},
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
        permissions=[permission],
        bindings=bindings_from_admin([assignment]),
    )
    principal = CedarEntity(type="AdminUser", id=str(admin_user), attributes={"tenant": "acme"})
    resource = CedarEntity(type="reports", id="*")
    assert engine.uses_cedarpy() is True
    assert (
        engine.check(
            principal=principal,
            action="reports:view",
            resource=resource,
            context={"tenant": "acme"},
        )
        is True
    )


def test_cedar_runtime_schema_exposes_context() -> None:
    now = _now()
    role_id = generate_id57()
    admin_user = generate_id57()
    role = Role(
        id=role_id,
        name="admin-analytics",
        scope=RoleScope.ADMIN,
        tenant=None,
        description=None,
        created_at=now,
        updated_at=now,
    )
    permission = Permission(
        id=generate_id57(),
        role_id=role_id,
        action="analytics:view",
        resource_type="analytics",
        effect=PermissionEffect.ALLOW,
        condition={"context_equals": {"tenant": "acme"}, "principal_attr_equals": {"tier": "gold"}},
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
        permissions=[permission],
        bindings=bindings_from_admin([assignment]),
    )
    runtime = getattr(engine, "_cedar_runtime")
    assert runtime is not None
    schema = json.loads(runtime._schema_json)
    action_schema = schema[""]["actions"]["analytics:view"]
    context_schema = action_schema["appliesTo"]["context"]["attributes"]
    assert context_schema == {"tenant": {"type": "String", "required": False}}
    principal_schema = schema[""]["entityTypes"]["AdminUser"]["shape"]["attributes"]
    assert principal_schema["tier"] == {"type": "String", "required": False}


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


def test_cedar_engine_deduplicates_candidates(monkeypatch) -> None:
    monkeypatch.setattr(rbac_module, "cedarpy", None)
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


def test_cedar_engine_returns_false_when_no_candidates(monkeypatch) -> None:
    monkeypatch.setattr(rbac_module, "cedarpy", None)
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("orders:read",),
        resource=CedarReference("orders", "*"),
    )
    engine = CedarEngine([policy])
    principal = CedarEntity(type="User", id="abc")
    resource = CedarEntity(type="orders", id="acme")
    assert engine.check(principal=principal, action="orders:write", resource=resource, context=None) is False


def test_cedar_engine_falls_back_for_manual_conditions() -> None:
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("noop",),
        resource=CedarReference("resource", "*"),
        condition=lambda _p, _a, _r, _c: True,
    )
    engine = CedarEngine([policy])
    assert engine.uses_cedarpy() is False
    principal = CedarEntity(type="User", id="abc")
    resource = CedarEntity(type="resource", id="item")
    assert engine.check(principal=principal, action="noop", resource=resource, context=None) is True


def test_cedar_engine_handles_none_resource_via_fallback() -> None:
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("noop",),
        resource=CedarReference("resource", "*"),
    )
    engine = CedarEngine([policy])
    principal = CedarEntity(type="User", id="abc")
    assert engine.uses_cedarpy() is True
    assert engine.check(principal=principal, action="noop", resource=None, context=None) is True


def test_cedar_runtime_build_skips_when_module_missing(monkeypatch) -> None:
    monkeypatch.setattr(rbac_module, "cedarpy", None)
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("noop",),
        resource=CedarReference("resource", "*"),
    )
    runtime = rbac_module._CedarPyRuntime.build([policy])
    assert runtime is None


def test_cedar_runtime_rejects_wildcard_resource() -> None:
    wildcard_policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("noop",),
        resource=CedarReference("*", "*"),
    )
    engine = CedarEngine([wildcard_policy])
    assert engine.uses_cedarpy() is False


def test_python_condition_checks_context_and_principal(monkeypatch) -> None:
    monkeypatch.setattr(rbac_module, "cedarpy", None)
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("noop",),
        resource=CedarReference("resource", "*"),
        condition=_condition_from_mapping(
            {"context_equals": {"tenant": "acme"}, "principal_attr_equals": {"tier": "gold"}}
        ),
        condition_data={"context_equals": {"tenant": "acme"}, "principal_attr_equals": {"tier": "gold"}},
    )
    engine = CedarEngine([policy])
    principal = CedarEntity(type="User", id="abc", attributes={"tier": "gold"})
    assert engine.check(
        principal=principal,
        action="noop",
        resource=CedarEntity(type="resource", id="any"),
        context={"tenant": "acme"},
    )
    assert (
        engine.check(
            principal=principal,
            action="noop",
            resource=CedarEntity(type="resource", id="any"),
            context={"tenant": "beta"},
        )
        is False
    )


def test_policy_action_keys_normalizes_wildcards() -> None:
    keys = rbac_module._policy_action_keys(["orders:read", "*", "orders:read"])
    assert keys == ("orders:read", None)


def test_python_fallback_returns_false_on_deny(monkeypatch) -> None:
    monkeypatch.setattr(rbac_module, "cedarpy", None)
    principal = CedarEntity(type="User", id="abc")
    resource = CedarEntity(type="orders", id="acme")
    allow = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("orders:read",),
        resource=CedarReference("orders", "*"),
    )
    deny = CedarPolicy(
        effect=CedarEffect.DENY,
        principal=CedarReference("User", "abc"),
        actions=("orders:read",),
        resource=CedarReference("orders", "*"),
    )
    engine = CedarEngine([allow, deny])
    assert engine.check(principal=principal, action="orders:read", resource=resource, context=None) is False


def test_condition_from_mapping_handles_partial_sections() -> None:
    gold = CedarEntity(type="User", id="abc", attributes={"tier": "gold"})
    silver = CedarEntity(type="User", id="abc", attributes={"tier": "silver"})
    only_principal = _condition_from_mapping({"principal_attr_equals": {"tier": "gold"}})
    assert only_principal is not None
    assert only_principal(gold, "noop", None, None) is True
    assert only_principal(silver, "noop", None, None) is False
    only_context = _condition_from_mapping({"context_equals": {"tenant": "acme"}})
    assert only_context is not None
    assert only_context(gold, "noop", None, {"tenant": "acme"}) is True
    assert only_context(gold, "noop", None, None) is False


def test_cedar_runtime_not_applicable_returns_false(monkeypatch) -> None:
    class DummyResult:
        def __init__(self, decision) -> None:
            self.decision = decision

    class DummyModule:
        class Decision:
            Allow = object()
            Deny = object()
            NotApplicable = object()

        def __init__(self) -> None:
            self.decision = self.Decision.NotApplicable

        def is_authorized(self, **_kwargs):
            return DummyResult(self.decision)

    monkeypatch.setattr(rbac_module, "cedarpy", DummyModule())
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("orders:read",),
        resource=CedarReference("orders", "acme"),
    )
    engine = CedarEngine([policy])
    principal = CedarEntity(type="User", id="abc")
    resource = CedarEntity(type="orders", id="acme")
    assert engine.uses_cedarpy() is True
    assert engine.check(principal=principal, action="orders:read", resource=resource, context=None) is False


def test_cedar_runtime_rejects_policy_with_no_actions() -> None:
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=(),
        resource=CedarReference("orders", "acme"),
    )
    runtime = rbac_module._CedarPyRuntime.build([policy])
    assert runtime is None


def test_cedar_runtime_rejects_policy_with_wildcard_action() -> None:
    policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("*",),
        resource=CedarReference("orders", "acme"),
    )
    runtime = rbac_module._CedarPyRuntime.build([policy])
    assert runtime is None


def test_cedar_policy_compiler_skips_wildcard_resources_in_schema() -> None:
    compiler = rbac_module._CedarPolicyCompiler.__new__(rbac_module._CedarPolicyCompiler)
    compiler._statements = ["permit(principal, action, resource);"]
    compiler._entity_types = {}
    compiler._context_attributes = {}
    compiler._actions = {"noop": {"principalTypes": {"User"}, "resourceTypes": {"orders"}}}
    compiler.supported = True
    wildcard_policy = CedarPolicy(
        effect=CedarEffect.ALLOW,
        principal=CedarReference("User", "abc"),
        actions=("noop",),
        resource=CedarReference("*", "*"),
    )
    compiler._finalize([wildcard_policy])
    schema = json.loads(compiler.schema_json)
    assert "*" not in schema[""]["entityTypes"]


def test_serialize_entity_skips_missing_attributes() -> None:
    entity = CedarEntity(type="User", id="abc", attributes=None)
    serialized = rbac_module._serialize_entity(entity, {"tier": "String"})
    assert serialized["attrs"] == {}


def test_serialize_entity_rejects_invalid_attribute_type() -> None:
    entity = CedarEntity(type="User", id="abc", attributes={"tier": "gold"})
    with pytest.raises(ValueError):
        rbac_module._serialize_entity(entity, {"tier": "Boolean"})


def test_render_condition_rejects_unsupported_context_values() -> None:
    context_attributes: dict[str, dict[str, str]] = {}
    principal_attributes: dict[str, dict[str, str]] = {}
    result = rbac_module._render_condition(
        lambda *_args: True,
        {"context_equals": {"tenant": ["acme"]}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert result is None


def test_render_condition_detects_conflicting_context_types() -> None:
    context_attributes: dict[str, dict[str, str]] = {}
    principal_attributes: dict[str, dict[str, str]] = {}
    first = rbac_module._render_condition(
        lambda *_args: True,
        {"context_equals": {"tenant": "acme"}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert first is not None
    conflict = rbac_module._render_condition(
        lambda *_args: True,
        {"context_equals": {"tenant": 1}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert conflict is None


def test_render_condition_allows_repeated_context_types() -> None:
    context_attributes: dict[str, dict[str, str]] = {}
    principal_attributes: dict[str, dict[str, str]] = {}
    first = rbac_module._render_condition(
        lambda *_args: True,
        {"context_equals": {"tenant": "acme"}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert first is not None
    repeated = rbac_module._render_condition(
        lambda *_args: True,
        {"context_equals": {"tenant": "beta"}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert repeated is not None


def test_render_condition_detects_conflicting_principal_types() -> None:
    context_attributes: dict[str, dict[str, str]] = {}
    principal_attributes: dict[str, dict[str, str]] = {}
    first = rbac_module._render_condition(
        lambda *_args: True,
        {"principal_attr_equals": {"tier": "gold"}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert first is not None
    conflict = rbac_module._render_condition(
        lambda *_args: True,
        {"principal_attr_equals": {"tier": True}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert conflict is None


def test_render_condition_allows_repeated_principal_types() -> None:
    context_attributes: dict[str, dict[str, str]] = {}
    principal_attributes: dict[str, dict[str, str]] = {}
    first = rbac_module._render_condition(
        lambda *_args: True,
        {"principal_attr_equals": {"tier": "gold"}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert first is not None
    repeated = rbac_module._render_condition(
        lambda *_args: True,
        {"principal_attr_equals": {"tier": "silver"}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert repeated is not None


def test_render_condition_rejects_unsupported_principal_values() -> None:
    context_attributes: dict[str, dict[str, str]] = {}
    principal_attributes: dict[str, dict[str, str]] = {}
    result = rbac_module._render_condition(
        lambda *_args: True,
        {"principal_attr_equals": {"tier": ["gold"]}},
        action="orders:read",
        principal_type="User",
        principal_attributes=principal_attributes,
        context_attributes=context_attributes,
    )
    assert result is None


def test_cedar_literal_and_type_helpers() -> None:
    assert rbac_module._cedar_literal("acme") == '"acme"'
    assert rbac_module._cedar_literal(True) == "true"
    assert rbac_module._cedar_literal(10) == "10"
    assert rbac_module._cedar_literal(1.2) is None
    assert rbac_module._cedar_type_for_value("acme") == "String"
    assert rbac_module._cedar_type_for_value(False) == "Boolean"
    assert rbac_module._cedar_type_for_value(5) == "Long"
    assert rbac_module._cedar_type_for_value(1.2) is None


def test_cedar_attribute_value_conversions() -> None:
    assert rbac_module._cedar_attribute_value("gold", "String") == "gold"
    assert rbac_module._cedar_attribute_value(True, "Boolean") is True
    assert rbac_module._cedar_attribute_value(5, "Long") == 5
    assert rbac_module._cedar_attribute_value("oops", "Long") is None
