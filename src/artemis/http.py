"""HTTP utilities and status code helpers."""

from __future__ import annotations

from enum import IntEnum
from http import HTTPStatus as _HTTPStatus


class Status(IntEnum):
    """Enumeration of the HTTP status codes used within the framework."""

    OK = 200
    CREATED = 201
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    GONE = 410
    PAYLOAD_TOO_LARGE = 413
    TOO_MANY_REQUESTS = 429
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501


def ensure_status(status: int | Status) -> int:
    """Normalize ``status`` to an ``int`` and ensure it is within the HTTP range."""

    code = int(status)
    if code < 100 or code > 599:
        raise ValueError(f"Invalid HTTP status code: {status}")
    return code


def reason_phrase(status: int | Status) -> str:
    """Return the HTTP reason phrase for ``status`` if known."""

    try:
        code = ensure_status(status)
    except ValueError:
        code = int(status)
        return "Unknown Status"
    try:
        return _HTTPStatus(code).phrase
    except ValueError:  # pragma: no cover - non-standard status codes
        return "Unknown Status"


def is_informational(status: int | Status) -> bool:
    """Return ``True`` if ``status`` is a 1xx code."""

    code = ensure_status(status)
    return 100 <= code < 200


def is_success(status: int | Status) -> bool:
    """Return ``True`` if ``status`` is a 2xx code."""

    code = ensure_status(status)
    return 200 <= code < 300


def is_redirect(status: int | Status) -> bool:
    """Return ``True`` if ``status`` is a 3xx code."""

    code = ensure_status(status)
    return 300 <= code < 400


def is_client_error(status: int | Status) -> bool:
    """Return ``True`` if ``status`` is a 4xx code."""

    code = ensure_status(status)
    return 400 <= code < 500


def is_server_error(status: int | Status) -> bool:
    """Return ``True`` if ``status`` is a 5xx code."""

    code = ensure_status(status)
    return 500 <= code < 600


def is_error(status: int | Status) -> bool:
    """Return ``True`` if ``status`` is either a client or server error."""

    code = ensure_status(status)
    return code >= 400


__all__ = [
    "Status",
    "ensure_status",
    "is_client_error",
    "is_error",
    "is_informational",
    "is_redirect",
    "is_server_error",
    "is_success",
    "reason_phrase",
]
