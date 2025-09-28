from __future__ import annotations

from typing import Optional

import msgspec
import pytest

from mere.exceptions import HTTPError
from mere.typing_utils import convert_primitive


class ExampleStruct(msgspec.Struct):
    value: int


def test_convert_numeric_and_bool() -> None:
    assert convert_primitive("7", int, source="param") == 7
    assert convert_primitive("false", bool, source="flag") is False
    assert convert_primitive("text", str, source="text") == "text"


def test_convert_optional() -> None:
    result = convert_primitive("3", Optional[int], source="opt")
    assert result == 3


def test_convert_struct_raises() -> None:
    with pytest.raises(HTTPError):
        convert_primitive("payload", ExampleStruct, source="struct")


def test_convert_invalid_bool() -> None:
    with pytest.raises(HTTPError):
        convert_primitive("notabool", bool, source="flag")


def test_convert_optional_failure() -> None:
    with pytest.raises(HTTPError):
        convert_primitive("oops", Optional[int], source="opt")


def test_convert_list_error() -> None:
    with pytest.raises(HTTPError):
        convert_primitive("1,2", list[int], source="list")
