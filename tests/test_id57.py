import datetime as dt

import pytest

from artemis.id57 import ALPHABET, Id57Parts, base57_encode, decode57, generate_id57


def test_generate_id57_lexicographically_sorted() -> None:
    first = generate_id57(timestamp=dt.datetime(2024, 1, 1, tzinfo=dt.UTC))
    second = generate_id57(timestamp=dt.datetime(2024, 1, 1, 0, 0, 0, 1, tzinfo=dt.UTC))
    assert first < second
    assert len(first) == len(second) == 33
    for char in first + second:
        assert char in ALPHABET


def test_base57_round_trip() -> None:
    for value in (0, 1, 57, 58, 2**32, 2**63 - 1):
        encoded = base57_encode(value)
        assert decode57(encoded) == value


def test_base57_rejects_negative() -> None:
    with pytest.raises(ValueError):
        base57_encode(-5)


def test_generate_with_custom_parts() -> None:
    parts = (
        Id57Parts(lambda ts, _uuid_factory, _idx: 123, pad_to=5),
        Id57Parts(lambda _ts, _uuid_factory, index: index + 7, pad_to=5),
    )
    custom = generate_id57(timestamp=dt.datetime(2024, 1, 1, tzinfo=dt.UTC), parts=parts)
    assert len(custom) == 10


def test_generate_requires_parts() -> None:
    with pytest.raises(ValueError):
        generate_id57(parts=(part for part in ()))
