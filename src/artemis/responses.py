"""Response primitives."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterable

import msgspec

from .exceptions import HTTPError
from .http import Status
from .serialization import json_encode

if TYPE_CHECKING:  # pragma: no cover - typing helpers only
    from .requests import Request


Handler = Callable[["Request"], Awaitable["Response"]]

DEFAULT_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("strict-transport-security", "max-age=63072000; includeSubDomains; preload"),
    ("content-security-policy", "default-src 'self'"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("x-frame-options", "DENY"),
    ("permissions-policy", "geolocation=(), microphone=(), camera=()"),
    ("cross-origin-opener-policy", "same-origin"),
)

Headers = tuple[tuple[str, str], ...]


class Response(msgspec.Struct, frozen=True):
    """Immutable response payload."""

    status: int = int(Status.OK)
    headers: Headers = ()
    body: bytes = b""

    def with_headers(self, headers: Iterable[tuple[str, str]]) -> "Response":
        """Return a new response with ``headers`` appended."""

        return Response(status=self.status, headers=self.headers + tuple(headers), body=self.body)


def apply_default_security_headers(
    response: Response,
    *,
    headers: Iterable[tuple[str, str]] | None = None,
) -> Response:
    """Append default security headers to ``response`` when missing."""

    baseline = tuple(headers or DEFAULT_SECURITY_HEADERS)
    if not baseline:
        return response
    existing = {name.lower(): value for name, value in response.headers}
    additions = tuple((name, value) for name, value in baseline if name.lower() not in existing)
    if not additions:
        return response
    return response.with_headers(additions)


async def security_headers_middleware(request: "Request", handler: Handler) -> Response:
    """Ensure responses emitted by ``handler`` include hardened security headers."""

    response = await handler(request)
    return apply_default_security_headers(response)


def PlainTextResponse(
    text: str,
    *,
    status: int = int(Status.OK),
    headers: Iterable[tuple[str, str]] | None = None,
) -> Response:
    """Create a plain text response."""

    default_headers = (("content-type", "text/plain; charset=utf-8"),)
    combined = default_headers + tuple(headers or ())
    response = Response(status=status, headers=combined, body=text.encode("utf-8"))
    return apply_default_security_headers(response)


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
    response = Response(status=status, headers=combined, body=body)
    return apply_default_security_headers(response)


def exception_to_response(exc: HTTPError) -> Response:
    response = Response(
        status=exc.status,
        headers=(("content-type", "application/json"),),
        body=exc.to_response_body(),
    )
    return apply_default_security_headers(response)


__all__ = [
    "DEFAULT_SECURITY_HEADERS",
    "JSONResponse",
    "PlainTextResponse",
    "Response",
    "apply_default_security_headers",
    "exception_to_response",
    "security_headers_middleware",
]
