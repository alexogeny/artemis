from __future__ import annotations

from typing import Any, Protocol, cast

import msgspec
from msgspec import structs


class _JSONModule(Protocol):
    def encode(self, obj: Any) -> bytes: ...

    def decode(self, data: bytes) -> Any: ...


class _MsgpackModule(Protocol):
    def encode(self, obj: Any) -> bytes: ...

    def decode(self, data: bytes) -> Any: ...


_json = cast(_JSONModule, getattr(msgspec, "json"))
_msgpack = cast(_MsgpackModule, getattr(msgspec, "msgpack"))


def _sanitize_for_json(value: Any) -> Any:
    from .orm import Model as ORMModel

    if isinstance(value, ORMModel):
        info = getattr(value, "__model_info__", None)
        redacted = getattr(info, "redacted_fields", frozenset()) if info is not None else frozenset()
        payload = structs.asdict(value)
        return {
            key: _sanitize_for_json(val)
            for key, val in payload.items()
            if key not in redacted
        }
    if isinstance(value, dict):
        return {key: _sanitize_for_json(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize_for_json(item) for item in value]
    return value


def json_encode(value: Any) -> bytes:
    """Serialize ``value`` to JSON bytes using msgspec."""

    return _json.encode(_sanitize_for_json(value))


def json_decode(data: bytes) -> Any:
    """Deserialize JSON ``data`` into native Python values."""

    return _json.decode(data)


def msgpack_encode(value: Any) -> bytes:
    """Serialize ``value`` to msgpack bytes using msgspec."""

    return _msgpack.encode(value)


def msgpack_decode(data: bytes) -> Any:
    """Deserialize msgpack ``data`` into native Python values."""

    return _msgpack.decode(data)
