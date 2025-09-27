"""Declarative ORM for Artemis models."""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, ClassVar, Generic, Iterable, Mapping, Sequence, TypeVar, get_type_hints
from weakref import WeakSet

import msgspec
from msgspec.inspect import NODEFAULT, StructType, type_info

from .audit import DELETE, INSERT, UPDATE, AuditTrail, current_actor
from .database import Database, _quote_identifier
from .id57 import generate_id57
from .tenancy import TenantContext

M = TypeVar("M", bound="Model")


class Model(msgspec.Struct, frozen=True, omit_defaults=True, kw_only=True):
    """Base class for all ORM models.

    Every subclass is automatically tracked so that features such as the
    migration tooling can discover declared models without requiring manual
    registration.  Registries remain useful for runtime lookups, but the
    tracking performed here ensures that simply defining a subclass is enough
    for schema generation.
    """

    _declared_models: ClassVar[WeakSet[type["Model"]]] = WeakSet()

    def __init_subclass__(cls, **kwargs: Any) -> None:  # pragma: no cover - exercised indirectly
        super().__init_subclass__(**kwargs)
        if cls is Model:
            return
        if getattr(cls, "__abstract__", False):
            return
        Model._declared_models.add(cls)

    @classmethod
    def declared_models(cls) -> tuple[type["Model"], ...]:
        """Return all known ``Model`` subclasses."""

        return tuple(cls._declared_models)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class DatabaseModel(Model, kw_only=True):
    """Base model including identifier and audit metadata."""

    __abstract__ = True

    id: str = msgspec.field(default_factory=generate_id57)
    created_at: dt.datetime = msgspec.field(default_factory=_utcnow)
    created_by: str | None = msgspec.field(default=None)
    updated_at: dt.datetime = msgspec.field(default_factory=_utcnow)
    updated_by: str | None = msgspec.field(default=None)
    deleted_at: dt.datetime | None = msgspec.field(default=None)
    deleted_by: str | None = msgspec.field(default=None)

    def __init_subclass__(cls, **kwargs: Any) -> None:  # pragma: no cover - exercised indirectly
        if cls is not DatabaseModel and "__abstract__" not in cls.__dict__:
            cls.__abstract__ = False
        super().__init_subclass__(**kwargs)


class ModelScope(str, Enum):
    """Supported model scopes."""

    ADMIN = "admin"
    TENANT = "tenant"


@dataclass(slots=True)
class FieldInfo:
    """Metadata describing a model field."""

    name: str
    column: str
    python_type: type[Any]
    has_default: bool
    default: Any
    default_factory: Callable[[], Any] | None


@dataclass(slots=True)
class ModelInfo(Generic[M]):
    """Metadata describing a registered model."""

    model: type[M]
    table: str
    scope: str
    schema: str | None
    identity: tuple[str, ...]
    fields: tuple[FieldInfo, ...]
    accessor: str
    field_map: Mapping[str, FieldInfo]
    exposed: bool
    redacted_fields: frozenset[str]


class ModelRegistry:
    """Registry mapping models to metadata for runtime lookups."""

    def __init__(self) -> None:
        self._models: dict[type[Model], ModelInfo[Any]] = {}
        self._accessors: dict[tuple[str, str], ModelInfo[Any]] = {}

    def register(self, info: ModelInfo[Any]) -> None:
        if info.model in self._models:
            raise ValueError(f"Model {info.model.__name__} already registered")
        accessor_key = (info.scope, info.accessor)
        if accessor_key in self._accessors:
            raise ValueError(f"Accessor '{info.accessor}' already registered for scope {info.scope}")
        self._models[info.model] = info
        self._accessors[accessor_key] = info

    def info_for(self, model: type[M]) -> ModelInfo[M]:
        try:
            info = self._models[model]
        except KeyError as exc:  # pragma: no cover - defensive branch
            raise LookupError(f"Model {model.__name__} is not registered") from exc
        return info  # type: ignore[return-value]

    def get_by_accessor(self, scope: str, accessor: str) -> ModelInfo[Any]:
        try:
            return self._accessors[(scope, accessor)]
        except KeyError as exc:
            raise LookupError(f"Model accessor '{accessor}' not registered for scope {scope}") from exc

    def models(self) -> Iterable[ModelInfo[Any]]:
        return self._models.values()


_default_registry = ModelRegistry()


def default_registry() -> ModelRegistry:
    """Return the shared global registry."""

    return _default_registry


def model(
    *,
    scope: ModelScope,
    table: str,
    schema: str | None = None,
    identity: Sequence[str] = ("id",),
    accessor: str | None = None,
    registry: ModelRegistry | None = None,
    exposed: bool = True,
    redacted_fields: Sequence[str] = (),
) -> Callable[[type[M]], type[M]]:
    """Class decorator used to register ORM models."""

    def decorator(cls: type[M]) -> type[M]:
        reg = registry or _default_registry
        info = _build_model_info(
            cls,
            scope=scope.value,
            table=table,
            schema=schema,
            identity=tuple(identity),
            accessor=accessor or table,
            exposed=exposed,
            redacted_fields=tuple(redacted_fields),
        )
        setattr(cls, "__model_info__", info)
        reg.register(info)
        return cls

    return decorator


class ORM:
    """Runtime object responsible for executing SQL for models."""

    def __init__(
        self,
        database: Database,
        registry: ModelRegistry | None = None,
        *,
        audit_trail: AuditTrail | None = None,
    ) -> None:
        self.database = database
        self.registry = registry or _default_registry
        self._audit_trail = audit_trail
        self.admin = _Namespace(self, ModelScope.ADMIN.value)
        self.tenants = _Namespace(self, ModelScope.TENANT.value)

    def attach_audit_trail(self, audit_trail: AuditTrail) -> None:
        """Attach an :class:`~artemis.audit.AuditTrail` after initialization."""

        self._audit_trail = audit_trail

    async def insert(self, model: type[M], data: M | Mapping[str, Any], *, tenant: TenantContext | None = None) -> M:
        info = self.registry.info_for(model)
        self._ensure_exposed(info)
        instance = self._coerce_instance(info, data)
        return await self._insert(info, instance, tenant)

    async def select(
        self,
        model: type[M],
        *,
        tenant: TenantContext | None = None,
        filters: Mapping[str, Any] | None = None,
        order_by: Sequence[str] | None = None,
        limit: int | None = None,
    ) -> list[M]:
        info = self.registry.info_for(model)
        self._ensure_exposed(info)
        rows = await self._select(info, tenant=tenant, filters=filters, order_by=order_by, limit=limit)
        return [msgspec.convert(row, type=info.model) for row in rows]

    async def update(
        self,
        model: type[M],
        values: Mapping[str, Any],
        *,
        tenant: TenantContext | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> list[M]:
        info = self.registry.info_for(model)
        self._ensure_exposed(info)
        rows = await self._update(info, values, tenant=tenant, filters=filters)
        return [msgspec.convert(row, type=info.model) for row in rows]

    async def delete(
        self,
        model: type[M],
        *,
        tenant: TenantContext | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> int:
        info = self.registry.info_for(model)
        self._ensure_exposed(info)
        return await self._delete(info, tenant=tenant, filters=filters)

    def manager(self, model: type[M]) -> "ModelManager[M]":
        info = self.registry.info_for(model)
        self._ensure_exposed(info)
        return ModelManager(self, info)

    def _ensure_exposed(self, info: ModelInfo[Any]) -> None:
        if not info.exposed:
            raise PermissionError(f"Model {info.model.__name__} is restricted and cannot be accessed via the ORM")

    async def _insert(self, info: ModelInfo[M], instance: M, tenant: TenantContext | None) -> M:
        payload = msgspec.to_builtins(instance)
        _apply_insert_metadata(info, payload)
        columns: list[str] = []
        values: list[Any] = []
        for field in info.fields:
            if field.name not in payload:
                continue
            columns.append(_quote_identifier(field.column))
            values.append(payload[field.name])
        placeholders = ", ".join(f"${idx}" for idx in range(1, len(values) + 1))
        returning = self._projection(info)
        schema = self.database.schema_for_model(info, tenant)
        table = f"{_quote_identifier(schema)}.{_quote_identifier(info.table)}"
        sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) RETURNING {returning}"
        async with self.database.connection_for_model(info, tenant=tenant) as connection:
            rows = await connection.fetch_all(sql, values)
        if not rows:
            raise RuntimeError("Insert did not return any rows")  # pragma: no cover - safety net
        if self._audit_trail is not None:
            await self._audit_trail.record_model_change(
                info=info,
                action=INSERT,
                tenant=tenant,
                data=rows[0],
                changes=payload,
            )
        return msgspec.convert(rows[0], type=info.model)

    async def _select(
        self,
        info: ModelInfo[M],
        *,
        tenant: TenantContext | None,
        filters: Mapping[str, Any] | None,
        order_by: Sequence[str] | None,
        limit: int | None,
    ) -> list[dict[str, Any]]:
        where_clause, parameters = self._build_filters(info, filters)
        schema = self.database.schema_for_model(info, tenant)
        table = f"{_quote_identifier(schema)}.{_quote_identifier(info.table)}"
        sql = f"SELECT {self._projection(info)} FROM {table}"
        if where_clause:
            sql += f" WHERE {where_clause}"
        if order_by:
            sql += f" ORDER BY {', '.join(self._order_fragment(info, part) for part in order_by)}"
        if limit is not None:
            parameters.append(limit)
            sql += f" LIMIT ${len(parameters)}"
        async with self.database.connection_for_model(info, tenant=tenant) as connection:
            return await connection.fetch_all(sql, parameters)

    async def _update(
        self,
        info: ModelInfo[M],
        values: Mapping[str, Any],
        *,
        tenant: TenantContext | None,
        filters: Mapping[str, Any] | None,
    ) -> list[dict[str, Any]]:
        if not values:
            return await self._select(info, tenant=tenant, filters=filters, order_by=None, limit=None)
        update_values = dict(values)
        _apply_update_metadata(info, update_values)
        set_clause, parameters = self._build_set(info, update_values)
        where_clause, where_parameters = self._build_filters(info, filters, start=len(parameters) + 1)
        parameters.extend(where_parameters)
        schema = self.database.schema_for_model(info, tenant)
        table = f"{_quote_identifier(schema)}.{_quote_identifier(info.table)}"
        sql = f"UPDATE {table} SET {set_clause}"
        if where_clause:
            sql += f" WHERE {where_clause}"
        sql += f" RETURNING {self._projection(info)}"
        async with self.database.connection_for_model(info, tenant=tenant) as connection:
            rows = await connection.fetch_all(sql, parameters)
        if self._audit_trail is not None:
            for row in rows:
                await self._audit_trail.record_model_change(
                    info=info,
                    action=UPDATE,
                    tenant=tenant,
                    data=row,
                    changes=update_values,
                )
        return rows

    async def _delete(
        self,
        info: ModelInfo[M],
        *,
        tenant: TenantContext | None,
        filters: Mapping[str, Any] | None,
    ) -> int:
        where_clause, parameters = self._build_filters(info, filters)
        schema = self.database.schema_for_model(info, tenant)
        table = f"{_quote_identifier(schema)}.{_quote_identifier(info.table)}"
        sql = f"DELETE FROM {table}"
        if where_clause:
            sql += f" WHERE {where_clause}"
        sql += f" RETURNING {self._projection(info)}"
        async with self.database.connection_for_model(info, tenant=tenant) as connection:
            rows = await connection.fetch_all(sql, parameters)
        if self._audit_trail is not None:
            for row in rows:
                await self._audit_trail.record_model_change(
                    info=info,
                    action=DELETE,
                    tenant=tenant,
                    data=row,
                    changes={},
                )
        return len(rows)

    def _coerce_instance(self, info: ModelInfo[M], data: M | Mapping[str, Any]) -> M:
        if isinstance(data, info.model):
            return data
        return msgspec.convert(data, type=info.model)

    def _projection(self, info: ModelInfo[Any]) -> str:
        parts: list[str] = []
        for field in info.fields:
            column = _quote_identifier(field.column)
            if field.column != field.name:
                alias = _quote_identifier(field.name)
                parts.append(f"{column} AS {alias}")
            else:
                parts.append(column)
        return ", ".join(parts)

    def _order_fragment(self, info: ModelInfo[Any], expression: str) -> str:
        direction = "ASC"
        field_name = expression
        if expression.lower().endswith(" desc"):
            direction = "DESC"
            field_name = expression[: -len(" desc")]
        elif expression.lower().endswith(" asc"):
            field_name = expression[: -len(" asc")]
        field = self._resolve_field(info, field_name.strip())
        return f"{_quote_identifier(field.column)} {direction}"

    def _build_filters(
        self,
        info: ModelInfo[Any],
        filters: Mapping[str, Any] | None,
        *,
        start: int = 1,
    ) -> tuple[str, list[Any]]:
        if not filters:
            return "", []
        parts: list[str] = []
        parameters: list[Any] = []
        index = start
        for name, value in filters.items():
            field = self._resolve_field(info, name)
            parts.append(f"{_quote_identifier(field.column)} = ${index}")
            parameters.append(value)
            index += 1
        return " AND ".join(parts), parameters

    def _build_set(
        self,
        info: ModelInfo[Any],
        values: Mapping[str, Any],
    ) -> tuple[str, list[Any]]:
        parts: list[str] = []
        parameters: list[Any] = []
        for idx, (name, value) in enumerate(values.items(), start=1):
            field = self._resolve_field(info, name)
            parts.append(f"{_quote_identifier(field.column)} = ${idx}")
            parameters.append(value)
        return ", ".join(parts), parameters

    def _resolve_field(self, info: ModelInfo[Any], name: str) -> FieldInfo:
        try:
            return info.field_map[name]
        except KeyError as exc:
            raise LookupError(f"Unknown field '{name}' for model {info.model.__name__}") from exc


class ModelManager(Generic[M]):
    """Per-model convenience wrapper exposed on :class:`ORM`."""

    def __init__(self, orm: ORM, info: ModelInfo[M]) -> None:
        self._orm = orm
        self._info = info

    async def create(self, data: M | Mapping[str, Any], *, tenant: TenantContext | None = None) -> M:
        return await self._orm._insert(self._info, self._orm._coerce_instance(self._info, data), tenant)

    async def get(
        self,
        *,
        tenant: TenantContext | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> M | None:
        rows = await self._orm._select(self._info, tenant=tenant, filters=filters, order_by=None, limit=1)
        if not rows:
            return None
        return msgspec.convert(rows[0], type=self._info.model)

    async def list(
        self,
        *,
        tenant: TenantContext | None = None,
        filters: Mapping[str, Any] | None = None,
        order_by: Sequence[str] | None = None,
        limit: int | None = None,
    ) -> list[M]:
        rows = await self._orm._select(
            self._info,
            tenant=tenant,
            filters=filters,
            order_by=order_by,
            limit=limit,
        )
        return [msgspec.convert(row, type=self._info.model) for row in rows]

    async def update(
        self,
        values: Mapping[str, Any],
        *,
        tenant: TenantContext | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> list[M]:
        rows = await self._orm._update(self._info, values, tenant=tenant, filters=filters)
        return [msgspec.convert(row, type=self._info.model) for row in rows]

    async def delete(
        self,
        *,
        tenant: TenantContext | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> int:
        return await self._orm._delete(self._info, tenant=tenant, filters=filters)


class _Namespace:
    def __init__(self, orm: ORM, scope: str) -> None:
        self._orm = orm
        self._scope = scope
        self._cache: dict[str, ModelManager[Any]] = {}

    def __getattr__(self, item: str) -> ModelManager[Any]:
        if item.startswith("__"):
            raise AttributeError(item)
        try:
            return self._cache[item]
        except KeyError:
            info = self._orm.registry.get_by_accessor(self._scope, item)
            if not info.exposed:
                raise AttributeError(f"Model accessor '{item}' in scope '{self._scope}' is restricted")
            manager = ModelManager(self._orm, info)
            self._cache[item] = manager
            return manager


def _build_model_info(
    model: type[M],
    *,
    scope: str,
    table: str,
    schema: str | None,
    identity: tuple[str, ...],
    accessor: str,
    exposed: bool,
    redacted_fields: Sequence[str],
) -> ModelInfo[M]:
    metadata = type_info(model)
    if not isinstance(metadata, StructType):  # pragma: no cover - msgspec ensures this
        raise TypeError(f"Model {model!r} is not a msgspec.Struct")
    annotations = get_type_hints(model, include_extras=True)
    fields: list[FieldInfo] = []
    field_map: dict[str, FieldInfo] = {}
    for field in metadata.fields:
        python_type = annotations.get(field.name, Any)
        default = field.default if field.default is not NODEFAULT else msgspec.UNSET
        default_factory = field.default_factory if field.default_factory is not NODEFAULT else None
        info = FieldInfo(
            name=field.name,
            column=field.encode_name,
            python_type=python_type,
            has_default=field.required is False,
            default=default,
            default_factory=default_factory,
        )
        fields.append(info)
        field_map[field.name] = info
    redacted = frozenset(str(name) for name in redacted_fields)
    unknown = [name for name in redacted if name not in field_map]
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise ValueError(f"Unknown redacted field(s) {joined} for model {model.__name__}")
    return ModelInfo(
        model=model,
        table=table,
        scope=scope,
        schema=schema,
        identity=identity,
        fields=tuple(fields),
        accessor=_normalize_accessor(accessor),
        field_map=field_map,
        exposed=exposed,
        redacted_fields=redacted,
    )


_accessor_pattern = re.compile(r"[^a-z0-9_]+")


def _normalize_accessor(name: str) -> str:
    lowered = name.lower()
    normalized = _accessor_pattern.sub("_", lowered)
    return normalized.strip("_") or lowered


def _apply_insert_metadata(info: ModelInfo[Any], payload: dict[str, Any]) -> None:
    actor = current_actor()
    now = dt.datetime.now(dt.timezone.utc)
    if "created_at" in info.field_map and payload.get("created_at") is None:
        payload["created_at"] = now
    if "updated_at" in info.field_map and payload.get("updated_at") is None:
        payload["updated_at"] = payload.get("created_at", now)
    if actor is not None:
        if "created_by" in info.field_map and payload.get("created_by") is None:
            payload["created_by"] = actor.id
        if "updated_by" in info.field_map and payload.get("updated_by") is None:
            payload["updated_by"] = actor.id


def _apply_update_metadata(info: ModelInfo[Any], values: dict[str, Any]) -> None:
    actor = current_actor()
    now = dt.datetime.now(dt.timezone.utc)
    if "updated_at" in info.field_map:
        values["updated_at"] = now
    if actor is not None and "updated_by" in info.field_map:
        values["updated_by"] = actor.id


__all__ = [
    "ORM",
    "DatabaseModel",
    "FieldInfo",
    "Model",
    "ModelInfo",
    "ModelManager",
    "ModelRegistry",
    "ModelScope",
    "default_registry",
    "model",
]
