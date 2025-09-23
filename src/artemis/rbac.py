"""Cedar-style RBAC helpers for Artemis."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence

from .models import (
    AdminRoleAssignment,
    Permission,
    PermissionEffect,
    Role,
    RoleScope,
    UserRole,
)


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

    def check(
        self,
        *,
        principal: CedarEntity,
        action: str,
        resource: CedarEntity | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> bool:
        allowed = False
        for policy in self._candidates(principal, action):
            if not policy.matches(principal, action, resource, context):
                continue
            if policy.effect is CedarEffect.DENY:
                return False
            allowed = True
        return allowed

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
