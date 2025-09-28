import uuid

import pytest

from mere.id57 import ALPHABET, USING_RUST_BACKEND, base57_encode, decode57, generate_id57


def test_generate_id57_lexicographically_sorted() -> None:
    first = generate_id57(timestamp=1_000_000, uuid=0)
    second = generate_id57(timestamp=1_000_000, uuid=1)
    third = generate_id57(timestamp=1_000_001, uuid=0)
    assert first < second < third
    assert len(first) == len(second) == len(third) == 33
    assert all(char in ALPHABET for char in first + second + third)


def test_base57_round_trip() -> None:
    for value in (0, 1, 57, 58, 2**32, 2**63 - 1):
        encoded = base57_encode(value)
        assert decode57(encoded) == value


def test_base57_rejects_negative() -> None:
    with pytest.raises(ValueError):
        base57_encode(-5)


def test_generate_id57_allows_uuid_inputs() -> None:
    custom_uuid = uuid.UUID(int=987654321)
    token = generate_id57(timestamp=0, uuid=custom_uuid)
    assert decode57(token[:11]) == 0
    assert decode57(token[11:]) == custom_uuid.int


def test_rust_backend_is_loaded() -> None:
    assert USING_RUST_BACKEND is True
    assert generate_id57.__module__ == "id57._core"
