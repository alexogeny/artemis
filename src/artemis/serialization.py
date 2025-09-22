"""Typed helper wrappers around :mod:`msgspec` serialization APIs."""

from __future__ import annotations

from typing import Any, Protocol, cast

import msgspec


class _JSONModule(Protocol):
    def encode(self, obj: Any) -> bytes: ...

    def decode(self, data: bytes) -> Any: ...


class _MsgpackModule(Protocol):
    def encode(self, obj: Any) -> bytes: ...

    def decode(self, data: bytes) -> Any: ...


_json = cast(_JSONModule, getattr(msgspec, "json"))
_msgpack = cast(_MsgpackModule, getattr(msgspec, "msgpack"))


def json_encode(value: Any) -> bytes:
    """Serialize ``value`` to JSON bytes using msgspec."""

    return _json.encode(value)


def json_decode(data: bytes) -> Any:
    """Deserialize JSON ``data`` into native Python values."""

    return _json.decode(data)


def msgpack_encode(value: Any) -> bytes:
    """Serialize ``value`` to msgpack bytes using msgspec."""

    return _msgpack.encode(value)


def msgpack_decode(data: bytes) -> Any:
    """Deserialize msgpack ``data`` into native Python values."""

    return _msgpack.decode(data)
