from __future__ import annotations

from artemis.exceptions import HTTPError
from artemis.responses import PlainTextResponse, Response, exception_to_response
from artemis.serialization import json_decode


def test_plain_text_response_headers() -> None:
    response = PlainTextResponse("hello")
    assert response.body == b"hello"
    assert ("content-type", "text/plain; charset=utf-8") in response.headers


def test_response_with_headers() -> None:
    base = Response(status=204)
    updated = base.with_headers((("x-test", "1"),))
    assert updated.headers[-1] == ("x-test", "1")


def test_exception_to_response_serializes() -> None:
    error = HTTPError(400, "bad request")
    response = exception_to_response(error)
    data = json_decode(response.body)
    assert data == {"error": {"status": 400, "detail": "bad request"}}
