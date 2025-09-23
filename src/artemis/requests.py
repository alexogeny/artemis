"""Request primitives."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Any, Mapping, MutableMapping, TypeVar, get_type_hints
from urllib.parse import parse_qsl

import msgspec

from .audit import AuditActor, bind_actor
from .serialization import json_decode
from .tenancy import TenantContext
from .typing_utils import convert_primitive

if TYPE_CHECKING:
    from .rbac import CedarEntity

T = TypeVar("T")


@lru_cache(maxsize=None)
def _model_type_hints(model: type[Any]) -> Mapping[str, Any]:
    return get_type_hints(model)


class Request:
    """Immutable view of an incoming request."""

    __slots__ = (
        "_body",
        "_json_cache",
        "_query_params",
        "_raw_query",
        "headers",
        "method",
        "path",
        "path_params",
        "principal",
        "tenant",
    )

    def __init__(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str] | None = None,
        tenant: TenantContext,
        path_params: Mapping[str, str] | None = None,
        query_string: str | None = None,
        body: bytes | None = None,
        principal: "CedarEntity | None" = None,
    ) -> None:
        self.method = method.upper()
        self.path = path
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.tenant = tenant
        self.path_params = dict(path_params or {})
        self._raw_query = query_string or ""
        self._body = body or b""
        self._json_cache: Any = msgspec.UNSET
        self._query_params: MutableMapping[str, list[str]] | None = None
        self.principal = principal

    @staticmethod
    def _parse_query(raw: str) -> MutableMapping[str, list[str]]:
        parsed: MutableMapping[str, list[str]] = {}
        for key, value in parse_qsl(raw, keep_blank_values=True):
            parsed.setdefault(key, []).append(value)
        return parsed

    @property
    def query_params(self) -> MutableMapping[str, list[str]]:
        if self._query_params is None:
            self._query_params = self._parse_query(self._raw_query)
        return self._query_params

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name.lower(), default)

    def query(self, model: type[T]) -> T:
        """Decode query parameters into ``model`` using msgspec."""

        hints = _model_type_hints(model)
        converted: dict[str, Any] = {}
        for key, values in self.query_params.items():
            if not values:
                continue
            annotation = hints.get(key, str)
            converted[key] = convert_primitive(values[-1], annotation, source=f"query:{key}")
        return msgspec.convert(converted, type=model)

    async def json(self, model: type[T] | None = None) -> T | Any:
        """Decode the JSON body using :mod:`msgspec`."""

        if self._json_cache is msgspec.UNSET:
            if not self._body:
                self._json_cache = None
            else:
                self._json_cache = json_decode(self._body)
        if model is None:
            return self._json_cache
        return msgspec.convert(self._json_cache, type=model)

    def text(self) -> str:
        return self._body.decode()

    def body(self) -> bytes:
        return self._body

    def with_principal(self, principal: "CedarEntity | None") -> "Request":
        self.principal = principal
        if principal is None:
            bind_actor(None)
        else:
            bind_actor(
                AuditActor(
                    id=principal.id,
                    type=principal.type,
                    attributes=dict(principal.attributes or {}),
                )
            )
        return self
