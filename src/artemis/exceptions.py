"""Framework exception types."""

from __future__ import annotations

from typing import Any

from .serialization import json_encode


class ArtemisError(Exception):
    """Base error type."""


class HTTPError(ArtemisError):
    """Structured HTTP error that is msgspec serializable."""

    def __init__(self, status: int, detail: Any) -> None:
        super().__init__(status, detail)
        self.status = status
        self.detail = detail

    def to_response_body(self) -> bytes:
        return json_encode({"error": {"status": self.status, "detail": self.detail}})
