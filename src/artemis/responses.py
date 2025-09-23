"""Response primitives."""

from __future__ import annotations

from typing import Any, Iterable

import msgspec

from .exceptions import HTTPError
from .http import Status
from .serialization import json_encode

Headers = tuple[tuple[str, str], ...]


class Response(msgspec.Struct, frozen=True):
    """Immutable response payload."""

    status: int = int(Status.OK)
    headers: Headers = ()
    body: bytes = b""

    def with_headers(self, headers: Iterable[tuple[str, str]]) -> "Response":
        """Return a new response with ``headers`` appended."""

        return Response(status=self.status, headers=self.headers + tuple(headers), body=self.body)


def PlainTextResponse(
    text: str,
    *,
    status: int = int(Status.OK),
    headers: Iterable[tuple[str, str]] | None = None,
) -> Response:
    """Create a plain text response."""

    default_headers = (("content-type", "text/plain; charset=utf-8"),)
    combined = default_headers + tuple(headers or ())
    return Response(status=status, headers=combined, body=text.encode("utf-8"))


def JSONResponse(
    data: Any,
    *,
    status: int = int(Status.OK),
    headers: Iterable[tuple[str, str]] | None = None,
) -> Response:
    """Create a JSON response encoded via :mod:`msgspec`."""

    default_headers = (("content-type", "application/json"),)
    combined = default_headers + tuple(headers or ())
    body = json_encode(data)
    return Response(status=status, headers=combined, body=body)


def exception_to_response(exc: HTTPError) -> Response:
    return Response(status=exc.status, headers=(("content-type", "application/json"),), body=exc.to_response_body())
