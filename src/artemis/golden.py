"""Golden file utilities used for contract testing."""

from __future__ import annotations

import base64
import difflib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from .responses import Response
from .serialization import json_decode

_APPROVAL_ENV_VARS: tuple[str, ...] = ("ARTEMIS_APPROVE_GOLDEN", "APPROVE_GOLDEN", "APPROVE")


class GoldenFile:
    """Manage serialized snapshots stored in the repository."""

    def __init__(self, path: str | Path, *, approval_env: Iterable[str] | None = None) -> None:
        self.path = Path(path)
        self._approval_env = tuple(approval_env or _APPROVAL_ENV_VARS)

    def ensure(self, data: Any) -> None:
        """Assert that ``data`` matches the stored golden file."""

        rendered = self._render(data)
        existing = self.path.read_text() if self.path.exists() else None
        if existing == rendered:
            return
        if self._should_approve():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(rendered)
            return
        diff = self._diff(existing or "", rendered)
        hint = self._approval_env[0] if self._approval_env else "ARTEMIS_APPROVE_GOLDEN"
        message = f"Golden file {self.path} is out of date. Set {hint}=1 to approve updates.\n{diff}".rstrip()
        raise AssertionError(message)

    def _should_approve(self) -> bool:
        for name in self._approval_env:
            value = os.getenv(name)
            if value and value.lower() not in {"0", "false"}:
                return True
        return False

    @staticmethod
    def _diff(original: str, updated: str) -> str:
        lines = difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile="expected",
            tofile="current",
        )
        return "".join(lines)

    @staticmethod
    def _render(data: Any) -> str:
        if isinstance(data, str):
            text = data
        else:
            text = json.dumps(data, indent=2, sort_keys=True)
        return text if text.endswith("\n") else f"{text}\n"


class RequestResponseRecorder:
    """Capture request/response pairs for deterministic replay."""

    def __init__(self, golden: GoldenFile) -> None:
        self._golden = golden
        self._entries: list[dict[str, Any]] = []

    def record(
        self,
        *,
        name: str,
        method: str,
        path: str,
        host: str,
        tenant: str,
        headers: Mapping[str, str],
        query: Mapping[str, Any] | None,
        json_body: Any | None,
        response: Response,
    ) -> None:
        entry: dict[str, Any] = {
            "name": name,
            "request": self._serialize_request(
                method=method,
                path=path,
                host=host,
                tenant=tenant,
                headers=headers,
                query=query,
                json_body=json_body,
            ),
            "response": self._serialize_response(response),
        }
        self._entries.append(entry)

    def finalize(self) -> None:
        """Write or validate the recorded interactions."""

        self._golden.ensure(self._entries)

    def __enter__(self) -> "RequestResponseRecorder":  # pragma: no cover - convenience wrapper
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # pragma: no cover - convenience wrapper
        if exc_type is None:
            self.finalize()

    @staticmethod
    def _serialize_request(
        *,
        method: str,
        path: str,
        host: str,
        tenant: str,
        headers: Mapping[str, str],
        query: Mapping[str, Any] | None,
        json_body: Any | None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "method": method,
            "path": path,
            "host": host,
            "tenant": tenant,
        }
        header_items = RequestResponseRecorder._header_items(headers)
        if header_items:
            data["headers"] = header_items
        if query:
            data["query"] = RequestResponseRecorder._normalize_query(query)
        if json_body is not None:
            data["json"] = json_body
        return data

    @staticmethod
    def _serialize_response(response: Response) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": response.status,
        }
        header_items = RequestResponseRecorder._header_items(dict(response.headers))
        if header_items:
            payload["headers"] = header_items
        json_body, text_body = RequestResponseRecorder._decode_body(response.body)
        if json_body is not None:
            payload["body"] = {"json": json_body}
        elif text_body is not None:
            payload["body"] = {"text": text_body}
        return payload

    @staticmethod
    def _header_items(headers: Mapping[str, str]) -> list[tuple[str, str]]:
        return sorted(((key.lower(), value) for key, value in headers.items()), key=lambda item: item[0])

    @staticmethod
    def _normalize_query(query: Mapping[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key in sorted(query):
            value = query[key]
            if isinstance(value, tuple):
                normalized[key] = list(value)
            elif isinstance(value, list):
                normalized[key] = [item for item in value]
            else:
                normalized[key] = value
        return normalized

    @staticmethod
    def _decode_body(body: bytes) -> tuple[Any | None, str | None]:
        if not body:
            return None, None
        try:
            return json_decode(body), None
        except Exception:  # pragma: no cover - defensive decoding
            try:
                return None, body.decode("utf-8")
            except UnicodeDecodeError:
                encoded = base64.b64encode(body).decode("ascii")
                return None, f"base64:{encoded}"


__all__ = ["GoldenFile", "RequestResponseRecorder"]
