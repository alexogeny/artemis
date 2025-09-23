from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from artemis.golden import GoldenFile, RequestResponseRecorder
from artemis.responses import JSONResponse, PlainTextResponse, Response


def _read_json(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text())
    assert isinstance(data, list)
    return cast(list[dict[str, Any]], data)


def test_golden_ensure_writes_when_approved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "value.json"
    golden = GoldenFile(path)
    monkeypatch.setenv("ARTEMIS_APPROVE_GOLDEN", "1")
    golden.ensure({"value": 1})
    monkeypatch.delenv("ARTEMIS_APPROVE_GOLDEN", raising=False)
    golden.ensure({"value": 1})
    assert path.read_text().endswith("\n")

    text_path = tmp_path / "note.txt"
    text_golden = GoldenFile(text_path)
    monkeypatch.setenv("ARTEMIS_APPROVE_GOLDEN", "1")
    text_golden.ensure("hello")
    monkeypatch.delenv("ARTEMIS_APPROVE_GOLDEN", raising=False)
    assert text_path.read_text() == "hello\n"


def test_golden_detects_differences(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "value.json"
    path.write_text("{\n  \"value\": 1\n}\n")
    golden = GoldenFile(path)
    monkeypatch.delenv("ARTEMIS_APPROVE_GOLDEN", raising=False)
    with pytest.raises(AssertionError) as excinfo:
        golden.ensure({"value": 2})
    message = str(excinfo.value)
    assert "Set ARTEMIS_APPROVE_GOLDEN=1 to approve updates." in message
    assert "-  \"value\": 1" in message
    assert "+  \"value\": 2" in message


def test_request_response_recorder_serializes_payloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "recordings.json"
    golden = GoldenFile(path)
    monkeypatch.setenv("ARTEMIS_APPROVE_GOLDEN", "1")
    recorder = RequestResponseRecorder(golden)

    recorder.record(
        name="json",
        method="POST",
        path="/items",
        host="acme.demo.example.com",
        tenant="acme",
        headers={"content-type": "application/json", "X-Test": "true"},
        query={"tag": ("a", "b"), "filters": ["x", "y"], "page": 1},
        json_body={"name": "Widget"},
        response=JSONResponse({"ok": True}, status=201, headers=(("x-trace", "abc"),)),
    )

    recorder.record(
        name="text",
        method="GET",
        path="/ping",
        host="demo.example.com",
        tenant="public",
        headers={},
        query={},
        json_body=None,
        response=PlainTextResponse("pong"),
    )

    recorder.record(
        name="binary",
        method="GET",
        path="/blob",
        host="demo.example.com",
        tenant="public",
        headers={},
        query={},
        json_body=None,
        response=Response(status=200, headers=(), body=b"\xff\x00"),
    )

    recorder.record(
        name="empty",
        method="HEAD",
        path="/ping",
        host="demo.example.com",
        tenant="public",
        headers={},
        query={},
        json_body=None,
        response=Response(status=204, headers=(), body=b""),
    )

    recorder.finalize()

    data = _read_json(path)
    assert data[0]["name"] == "json"

    first_request = data[0]["request"]
    assert isinstance(first_request, dict)
    request_headers = first_request["headers"]
    assert isinstance(request_headers, list)
    assert request_headers[0] == ["content-type", "application/json"]
    assert request_headers[1] == ["x-test", "true"]
    assert first_request["query"] == {"filters": ["x", "y"], "page": 1, "tag": ["a", "b"]}

    first_response = data[0]["response"]
    assert isinstance(first_response, dict)
    response_body = first_response["body"]
    assert isinstance(response_body, dict)
    assert response_body["json"] == {"ok": True}

    second_response = data[1]["response"]
    assert isinstance(second_response, dict)
    assert second_response["body"] == {"text": "pong"}

    third_response = data[2]["response"]
    assert isinstance(third_response, dict)
    assert third_response["body"] == {"text": "base64:/wA="}

    second_request = data[1]["request"]
    assert isinstance(second_request, dict)
    assert "json" not in second_request

    fourth_response = data[3]["response"]
    assert isinstance(fourth_response, dict)
    assert "body" not in fourth_response
