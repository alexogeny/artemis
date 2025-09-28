"""Framework exception types."""

from __future__ import annotations

from typing import Any

from .http import Status, ensure_status, reason_phrase
from .serialization import json_encode


class MereError(Exception):
    """Base error type."""


class HTTPError(MereError):
    """Structured HTTP error that is msgspec serializable."""

    def __init__(self, status: int | Status, detail: Any) -> None:
        status_code = ensure_status(status)
        super().__init__(status_code, detail)
        self.status = status_code
        self.detail = detail
        self.reason = reason_phrase(status_code)

    def to_response_body(self) -> bytes:
        return json_encode({"error": {"status": self.status, "reason": self.reason, "detail": self.detail}})
