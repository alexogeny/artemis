"""Shared conversion helpers."""

from __future__ import annotations

from typing import Any, Union, get_args, get_origin

import msgspec

from .exceptions import HTTPError
from .http import Status

Primitive = Union[str, int, float, bool]


def convert_primitive(value: str, annotation: Any, *, source: str) -> Any:
    """Convert a string ``value`` into ``annotation`` raising :class:`HTTPError` on failure."""

    origin = get_origin(annotation)
    if origin is Union:
        for option in get_args(annotation):
            if option is type(None):
                continue
            try:
                return convert_primitive(value, option, source=source)
            except HTTPError:
                continue
        raise HTTPError(Status.BAD_REQUEST, {"source": source, "expected": repr(annotation), "value": value})
    if isinstance(annotation, type) and issubclass(annotation, msgspec.Struct):
        try:
            return msgspec.convert(value, type=annotation)
        except msgspec.ValidationError as exc:  # pragma: no cover - defensive
            raise HTTPError(
                Status.BAD_REQUEST,
                {"source": source, "expected": annotation.__name__, "value": value},
            ) from exc
    return _convert_simple(value, annotation, source=source)


def _convert_simple(value: str, annotation: Any, *, source: str) -> Any:
    if annotation in {int, float}:
        try:
            return annotation(value)
        except ValueError as exc:
            raise HTTPError(
                Status.BAD_REQUEST,
                {"source": source, "expected": annotation.__name__, "value": value},
            ) from exc
    if annotation is bool:
        lowered = value.lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
        raise HTTPError(Status.BAD_REQUEST, {"source": source, "expected": "bool", "value": value})
    if annotation in {str, Any} or annotation is None:
        return value
    try:
        return msgspec.convert(value, type=annotation)
    except msgspec.ValidationError as exc:
        raise HTTPError(
            Status.BAD_REQUEST,
            {"source": source, "expected": repr(annotation), "value": value},
        ) from exc
