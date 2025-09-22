"""Utilities for generating lexicographically sortable ``id57`` identifiers."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable

__all__ = [
    "ALPHABET",
    "Id57Parts",
    "base57_encode",
    "decode57",
    "generate_id57",
]


# ``id57`` excludes characters that are commonly confused with one another.  The
# alphabet is ordered from the smallest ASCII code point upward so that
# lexicographical ordering matches numeric ordering when identifiers are padded.
ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE = len(ALPHABET)


@dataclass(slots=True, frozen=True)
class Id57Parts:
    """Composable parts used to construct a final ``id57`` value."""

    value_factory: Callable[[dt.datetime, Callable[[], uuid.UUID], int], int]
    pad_to: int

    def render(self, *, timestamp: dt.datetime, uuid_factory: Callable[[], uuid.UUID], index: int) -> str:
        return base57_encode(self.value_factory(timestamp, uuid_factory, index), pad_to=self.pad_to)


def base57_encode(value: int, *, pad_to: int | None = None) -> str:
    """Encode ``value`` as a base57 string using the ``id57`` alphabet."""

    if value < 0:
        raise ValueError("id57 only supports unsigned integers")
    if value == 0:
        encoded = ALPHABET[0]
    else:
        digits: list[str] = []
        number = value
        while number:
            number, remainder = divmod(number, _BASE)
            digits.append(ALPHABET[remainder])
        encoded = "".join(reversed(digits))
    if pad_to is not None and pad_to > len(encoded):
        encoded = ALPHABET[0] * (pad_to - len(encoded)) + encoded
    return encoded


def decode57(value: str) -> int:
    """Decode a base57 string back into an integer."""

    number = 0
    for char in value:
        try:
            digit = ALPHABET.index(char)
        except ValueError as exc:  # pragma: no cover - defensive branch
            raise ValueError(f"Character {char!r} is not valid for id57") from exc
        number = number * _BASE + digit
    return number


def generate_id57(
    *,
    timestamp: dt.datetime | None = None,
    random_source: Callable[[], uuid.UUID] | None = None,
    parts: Iterable[Id57Parts] | None = None,
) -> str:
    """Generate a new lexicographically sortable identifier."""

    ts = timestamp or dt.datetime.now(dt.UTC)
    uuid_factory = random_source or uuid.uuid4
    default_parts = (
        Id57Parts(lambda ts, _uuid_factory, _idx: int(ts.timestamp() * 1_000_000), pad_to=11),
        Id57Parts(lambda _ts, uuid_factory, _idx: uuid_factory().int, pad_to=22),
    )
    segments: list[str] = []
    components = list(parts or default_parts)
    if not components:
        raise ValueError("id57 requires at least one component")
    for index, component in enumerate(components):
        segments.append(
            component.render(timestamp=ts, uuid_factory=uuid_factory, index=index)
        )
    return "".join(segments)

