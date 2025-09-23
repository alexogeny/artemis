from __future__ import annotations

import pytest

from artemis.http import (
    Status,
    ensure_status,
    is_client_error,
    is_error,
    is_informational,
    is_redirect,
    is_server_error,
    is_success,
    reason_phrase,
)


def test_ensure_status_validates_range() -> None:
    assert ensure_status(Status.OK) == 200
    assert ensure_status(404) == 404
    with pytest.raises(ValueError):
        ensure_status(99)
    with pytest.raises(ValueError):
        ensure_status(600)


def test_reason_phrase_for_known_and_unknown_statuses() -> None:
    assert reason_phrase(Status.OK) == "OK"
    assert reason_phrase(418) == "I'm a Teapot"
    assert reason_phrase(799) == "Unknown Status"


def test_status_category_helpers() -> None:
    assert is_informational(101)
    assert not is_informational(Status.OK)
    assert is_success(Status.OK)
    assert not is_success(Status.BAD_REQUEST)
    assert is_redirect(302)
    assert is_client_error(Status.BAD_REQUEST)
    assert is_server_error(Status.INTERNAL_SERVER_ERROR)
    assert is_error(Status.BAD_REQUEST)
    assert is_error(Status.INTERNAL_SERVER_ERROR)
    assert not is_error(Status.NO_CONTENT)
