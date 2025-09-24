"""Cedar-style RBAC helpers for Artemis."""

from __future__ import annotations

import importlib.util
import json
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from types import ModuleType
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping, Sequence

from .models import (
    AdminRoleAssignment,
    Permission,
    PermissionEffect,
    Role,
    RoleScope,
    UserRole,
)

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    import cedarpy

cedarpy: ModuleType | None
if importlib.util.find_spec("cedarpy") is not None:  # pragma: no cover - import guard
    import cedarpy as _cedarpy

    cedarpy = _cedarpy
else:  # pragma: no cover - fallback when cedarpy is unavailable
    cedarpy = None


class CedarEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(slots=True, frozen=True)
class CedarEntity:
    type: str
    id: str
    attributes: Mapping[str, Any] | None = None

    def attribute(self, name: str, default: Any | None = None) -> Any | None:
        return (self.attributes or {}).get(name, default)


@dataclass(slots=True, frozen=True)
class CedarReference:
    entity_type: str
    identifier: str | None = None

    def matches(self, entity: CedarEntity) -> bool:
        if self.entity_type != "*" and self.entity_type != entity.type:
            return False
        if self.identifier in (None, "*"):
            return True
        return entity.id == self.identifier


Condition = Callable[[CedarEntity, str, CedarEntity | None, Mapping[str, Any] | None], bool]


@dataclass(slots=True, frozen=True)
class CedarPolicy:
    effect: CedarEffect
    principal: CedarReference
    actions: tuple[str, ...]
    resource: CedarReference
    condition: Condition | None = None
    condition_data: Mapping[str, Any] | None = field(default=None, repr=False)

    def matches(
        self,
        principal: CedarEntity,
        action: str,
        resource: CedarEntity | None,
        context: Mapping[str, Any] | None,
    ) -> bool:
        if not self.principal.matches(principal):
            return False
        if self.actions and action not in self.actions:
            return False
        if resource is not None and not self.resource.matches(resource):
            return False
        if self.condition is None:
            return True
        return self.condition(principal, action, resource, context)


@dataclass(slots=True, frozen=True)
class RoleBinding:
    principal_type: str
    principal_id: str
    role_id: str


class CedarEngine:
    """Evaluate Cedar policies following deny-overrides semantics."""

    def __init__(self, policies: Sequence[CedarPolicy]) -> None:
        self._policies = tuple(policies)
        self._index = self._build_index(self._policies)
        self._cedar_runtime = _CedarPyRuntime.build(self._policies)

    def check(
        self,
        *,
        principal: CedarEntity,
        action: str,
        resource: CedarEntity | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> bool:
        if self._cedar_runtime is not None:
            compiled = self._cedar_runtime.check(
                principal=principal,
                action=action,
                resource=resource,
                context=context,
            )
            if compiled is not None:
                return compiled
        allowed = False
        for policy in self._candidates(principal, action):
            if not policy.matches(principal, action, resource, context):
                continue
            if policy.effect is CedarEffect.DENY:
                return False
            allowed = True
        return allowed

    def uses_cedarpy(self) -> bool:
        return self._cedar_runtime is not None

    def policies(self) -> Sequence[CedarPolicy]:
        return self._policies

    def _build_index(
        self, policies: Sequence[CedarPolicy]
    ) -> Mapping[str | None, Mapping[str | None, Mapping[str | None, tuple[CedarPolicy, ...]]]]:
        index: dict[str | None, dict[str | None, dict[str | None, list[CedarPolicy]]]] = {}
        for policy in policies:
            type_key = policy.principal.entity_type
            if type_key == "*":
                type_key = None
            identifier = policy.principal.identifier
            if identifier in (None, "*"):
                id_key: str | None = None
            else:
                id_key = identifier
            action_keys = _policy_action_keys(policy.actions)
            type_bucket = index.setdefault(type_key, {})
            id_bucket = type_bucket.setdefault(id_key, {})
            for action_key in action_keys:
                id_bucket.setdefault(action_key, []).append(policy)
        return {
            type_key: {
                id_key: {action: tuple(policies) for action, policies in action_map.items()}
                for id_key, action_map in id_bucket.items()
            }
            for type_key, id_bucket in index.items()
        }

    def _candidates(self, principal: CedarEntity, action: str) -> Sequence[CedarPolicy]:
        candidates: list[CedarPolicy] = []
        for type_key in (principal.type, None):
            type_bucket = self._index.get(type_key)
            if not type_bucket:
                continue
            for id_key in (principal.id, None):
                action_bucket = type_bucket.get(id_key)
                if not action_bucket:
                    continue
                policies = action_bucket.get(action)
                if policies:
                    candidates.extend(policies)
                wildcard = action_bucket.get(None)
                if wildcard:
                    candidates.extend(wildcard)
        if not candidates:
            return ()
        seen: set[int] = set()
        unique: list[CedarPolicy] = []
        for policy in candidates:
            identifier = id(policy)
            if identifier in seen:
                continue
            seen.add(identifier)
            unique.append(policy)
        return unique


def bindings_from_admin(assignments: Iterable[AdminRoleAssignment]) -> list[RoleBinding]:
    return [RoleBinding("AdminUser", item.admin_user_id, item.role_id) for item in assignments]


def bindings_from_users(assignments: Iterable[UserRole]) -> list[RoleBinding]:
    return [RoleBinding("User", item.user_id, item.role_id) for item in assignments]


def build_engine(
    *,
    roles: Iterable[Role],
    permissions: Iterable[Permission],
    bindings: Iterable[RoleBinding],
) -> CedarEngine:
    role_index = {role.id: role for role in roles}
    permissions_by_role: dict[str, list[Permission]] = defaultdict(list)
    for permission in permissions:
        permissions_by_role[permission.role_id].append(permission)
    policies: list[CedarPolicy] = []
    for binding in bindings:
        role = role_index.get(binding.role_id)
        if role is None:
            continue
        for permission in permissions_by_role.get(role.id, []):
            policies.append(
                CedarPolicy(
                    effect=_to_effect(permission.effect),
                    principal=CedarReference(binding.principal_type, binding.principal_id),
                    actions=_normalize_actions(permission.action),
                    resource=_permission_resource(permission, role),
                    condition=_condition_from_mapping(permission.condition),
                    condition_data=permission.condition,
                )
            )
    return CedarEngine(policies)


def _normalize_actions(action: str) -> tuple[str, ...]:
    actions = [part.strip() for part in action.split(",") if part.strip()]
    return tuple(actions or [action])


def _policy_action_keys(actions: Sequence[str]) -> tuple[str | None, ...]:
    if not actions:
        return (None,)
    keys: list[str | None] = []
    for action in actions:
        normalized: str | None = action if action != "*" else None
        if normalized not in keys:
            keys.append(normalized)
    return tuple(keys or (None,))


def _permission_resource(permission: Permission, role: Role) -> CedarReference:
    tenant_target = permission.condition.get("tenant") if permission.condition else None
    resource_type = permission.resource_type
    if tenant_target:
        identifier = tenant_target
    elif role.scope is RoleScope.ADMIN:
        identifier = "*"
    else:
        identifier = role.tenant or "*"
    return CedarReference(resource_type, identifier)


def _condition_from_mapping(data: Mapping[str, Any] | None) -> Condition | None:
    if not data:
        return None
    context_equals = data.get("context_equals")
    principal_equals = data.get("principal_attr_equals")

    def evaluator(
        principal: CedarEntity,
        action: str,
        resource: CedarEntity | None,
        context: Mapping[str, Any] | None,
    ) -> bool:
        if context_equals:
            for key, expected in context_equals.items():
                if context is None or context.get(key) != expected:
                    return False
        if principal_equals:
            for key, expected in principal_equals.items():
                if principal.attribute(key) != expected:
                    return False
        return True

    return evaluator


def _to_effect(effect: PermissionEffect | str) -> CedarEffect:
    if isinstance(effect, PermissionEffect):
        return CedarEffect(effect.value)
    return CedarEffect(effect.lower())


class _CedarPyRuntime:
    __slots__ = (
        "_module",
        "_policies_text",
        "_principal_attributes",
        "_schema_json",
    )

    def __init__(
        self,
        *,
        module: ModuleType,
        policies_text: str,
        schema_json: str,
        principal_attributes: Mapping[str, Mapping[str, str]],
    ) -> None:
        self._module = module
        self._policies_text = policies_text
        self._schema_json = schema_json
        self._principal_attributes = {
            key: dict(value) for key, value in principal_attributes.items()
        }

    @classmethod
    def build(cls, policies: Sequence[CedarPolicy]) -> _CedarPyRuntime | None:
        module = cedarpy
        if module is None:
            return None
        compiler = _CedarPolicyCompiler(policies)
        if not compiler.supported:
            return None
        return cls(
            module=module,
            policies_text=compiler.policies_text,
            schema_json=compiler.schema_json,
            principal_attributes=compiler.principal_attributes,
        )

    def check(
        self,
        *,
        principal: CedarEntity,
        action: str,
        resource: CedarEntity | None,
        context: Mapping[str, Any] | None,
    ) -> bool | None:
        if resource is None:
            return None
        request = {
            "principal": _format_entity_reference(principal),
            "action": _action_literal(action),
            "resource": _format_entity_reference(resource),
        }
        if context is not None:
            request["context"] = context
        try:
            entities = json.dumps(
                [
                    _serialize_entity(principal, self._principal_attributes.get(principal.type, {})),
                    _serialize_entity(resource, {}),
                ]
            )
            result = self._module.is_authorized(
                request=request,
                policies=self._policies_text,
                entities=entities,
                schema=self._schema_json,
            )
        except Exception:  # pragma: no cover - cedar runtime failure falls back to python path
            return None
        if result.decision is self._module.Decision.Allow:
            return True
        if result.decision is self._module.Decision.Deny:
            return False
        return False


class _CedarPolicyCompiler:
    __slots__ = (
        "_actions",
        "_context_attributes",
        "_entity_types",
        "_principal_attributes",
        "_statements",
        "policies_text",
        "schema_json",
        "supported",
    )

    def __init__(self, policies: Sequence[CedarPolicy]) -> None:
        self.supported = True
        self._statements: list[str] = []
        self._entity_types: dict[str, dict[str, str]] = defaultdict(dict)
        self._context_attributes: dict[str, dict[str, str]] = defaultdict(dict)
        self._actions: dict[str, dict[str, set[str]]] = {}
        self._compile(policies)
        if self.supported:
            self._finalize(policies)

    @property
    def principal_attributes(self) -> Mapping[str, Mapping[str, str]]:
        return self._entity_types

    def _compile(self, policies: Sequence[CedarPolicy]) -> None:
        for index, policy in enumerate(policies):
            if not self._translate_policy(policy, index):
                self.supported = False
                return

    def _translate_policy(self, policy: CedarPolicy, index: int) -> bool:
        principal_clause, principal_type = _render_reference("principal", policy.principal)
        if principal_clause is None:
            return False
        resource_clause, resource_type = _render_reference("resource", policy.resource)
        if resource_clause is None:
            return False
        if not policy.actions:
            return False
        for action in policy.actions:
            if action == "*":
                return False
            when_clause = _render_condition(
                policy.condition,
                policy.condition_data,
                action=action,
                principal_type=principal_type,
                principal_attributes=self._entity_types,
                context_attributes=self._context_attributes,
            )
            if when_clause is None and policy.condition is not None:
                return False
            effect = "permit" if policy.effect is CedarEffect.ALLOW else "forbid"
            statement = (
                f"{effect}(\n"
                f"    {principal_clause},\n"
                f"    action == {_action_literal(action)},\n"
                f"    {resource_clause}\n"
                f"){when_clause};"
            )
            self._statements.append(statement)
            action_entry = self._actions.setdefault(action, {"principalTypes": set(), "resourceTypes": set()})
            action_entry["principalTypes"].add(principal_type)
            action_entry["resourceTypes"].add(resource_type)
        return True

    def _finalize(self, policies: Sequence[CedarPolicy]) -> None:
        if not self._statements:
            self.supported = False
            return
        entity_types: dict[str, Any] = {}
        for entity_type, attributes in self._entity_types.items():
            entity_types[entity_type] = {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        name: {"type": attr_type, "required": False}
                        for name, attr_type in sorted(attributes.items())
                    },
                }
            }
        for policy in policies:
            resource_type = policy.resource.entity_type
            if resource_type == "*":
                continue
            entity_types.setdefault(
                resource_type,
                {"shape": {"type": "Record", "attributes": {}}},
            )
        actions: dict[str, Any] = {}
        for action, data in self._actions.items():
            applies_to: dict[str, Any] = {
                "principalTypes": sorted(data["principalTypes"]),
                "resourceTypes": sorted(data["resourceTypes"]),
            }
            context_types = self._context_attributes.get(action)
            if context_types:
                applies_to["context"] = {
                    "type": "Record",
                    "attributes": {
                        name: {"type": attr_type, "required": False}
                        for name, attr_type in sorted(context_types.items())
                    },
                }
            actions[action] = {"appliesTo": applies_to}
        self.policies_text = "\n".join(self._statements)
        self.schema_json = json.dumps({"": {"entityTypes": entity_types, "actions": actions}})


def _format_entity_reference(entity: CedarEntity) -> str:
    return f"{entity.type}::\"{_escape_string(entity.id)}\""


def _action_literal(action: str) -> str:
    return f"Action::\"{_escape_string(action)}\""


def _serialize_entity(entity: CedarEntity, attribute_types: Mapping[str, str]) -> Mapping[str, Any]:
    attributes: dict[str, Any] = {}
    data = entity.attributes or {}
    for name, attr_type in attribute_types.items():
        if name not in data:
            continue
        value = _cedar_attribute_value(data[name], attr_type)
        if value is None:
            raise ValueError(f"Unsupported attribute type for {name!r}")
        attributes[name] = value
    return {
        "uid": {"type": entity.type, "id": entity.id},
        "attrs": attributes,
        "parents": [],
    }


def _render_reference(label: str, reference: CedarReference) -> tuple[str | None, str]:
    entity_type = reference.entity_type
    if entity_type == "*":
        return None, entity_type
    identifier = reference.identifier
    if identifier in (None, "*"):
        clause = f"{label} is {entity_type}"
    else:
        clause = f"{label} == {entity_type}::\"{_escape_string(identifier)}\""
    return clause, entity_type


def _render_condition(
    condition: Condition | None,
    data: Mapping[str, Any] | None,
    *,
    action: str,
    principal_type: str,
    principal_attributes: dict[str, dict[str, str]],
    context_attributes: dict[str, dict[str, str]],
) -> str | None:
    if data is None:
        return None if condition is not None else ""
    expressions: list[str] = []
    context_types = context_attributes.setdefault(action, {})
    for key, expected in (data.get("context_equals") or {}).items():
        literal = _cedar_literal(expected)
        attr_type = _cedar_type_for_value(expected)
        if literal is None or attr_type is None:
            return None
        existing = context_types.get(key)
        if existing is None:
            context_types[key] = attr_type
        elif existing != attr_type:
            return None
        expressions.append(f"context.{key} == {literal}")
    attr_types = principal_attributes.setdefault(principal_type, {})
    for key, expected in (data.get("principal_attr_equals") or {}).items():
        literal = _cedar_literal(expected)
        attr_type = _cedar_type_for_value(expected)
        if literal is None or attr_type is None:
            return None
        existing = attr_types.get(key)
        if existing is None:
            attr_types[key] = attr_type
        elif existing != attr_type:
            return None
        expressions.append(f"principal.{key} == {literal}")
    if not expressions:
        return ""
    return " when { " + " && ".join(expressions) + " }"


def _cedar_literal(value: Any) -> str | None:
    if isinstance(value, str):
        return f'"{_escape_string(value)}"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return None


def _cedar_type_for_value(value: Any) -> str | None:
    if isinstance(value, str):
        return "String"
    if isinstance(value, bool):
        return "Boolean"
    if isinstance(value, int):
        return "Long"
    return None


def _cedar_attribute_value(value: Any, attr_type: str) -> Any | None:
    if attr_type == "String" and isinstance(value, str):
        return value
    if attr_type == "Boolean" and isinstance(value, bool):
        return value
    if attr_type == "Long" and isinstance(value, int):
        return value
    return None


def _escape_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', "\\\"")


__all__ = [
    "CedarEffect",
    "CedarEngine",
    "CedarEntity",
    "CedarPolicy",
    "CedarReference",
    "RoleBinding",
    "bindings_from_admin",
    "bindings_from_users",
    "build_engine",
]
