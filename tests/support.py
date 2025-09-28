"""Test support utilities for Mere database and ORM tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Sequence

from mere.database import SecretRef


@dataclass
class FakeResult:
    rows: List[dict[str, Any]]

    def result(self) -> List[dict[str, Any]]:
        return self.rows


class FakeConnection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, list[Any], bool]] = []
        self._queued: list[list[dict[str, Any]]] = []

    def queue_result(self, rows: Iterable[dict[str, Any]]) -> None:
        self._queued.append([dict(row) for row in rows])

    async def execute(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        *,
        prepared: bool = False,
    ) -> FakeResult:
        params = list(parameters or [])
        self.calls.append(("execute", query, params, prepared))
        if query.lstrip().upper().startswith("SET "):
            return FakeResult([])
        rows = self._queued.pop(0) if self._queued else []
        return FakeResult(rows)

    async def execute_batch(self, query: str) -> None:
        self.calls.append(("execute_batch", query, [], False))


class _Acquire:
    def __init__(self, connection: FakeConnection) -> None:
        self._connection = connection

    async def __aenter__(self) -> FakeConnection:
        return self._connection

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class FakePool:
    def __init__(self, connection: FakeConnection | None = None) -> None:
        self.connection = connection or FakeConnection()
        self.closed = False

    def acquire(self) -> _Acquire:
        return _Acquire(self.connection)

    def close(self) -> None:
        self.closed = True


class StaticSecretResolver:
    def __init__(self, secrets: Mapping[tuple[str, str, str | None], str]) -> None:
        self._secrets = dict(secrets)
        self.calls: list[SecretRef] = []

    def resolve(self, secret: SecretRef) -> str:
        self.calls.append(secret)
        key = (secret.provider, secret.name, secret.version)
        try:
            return self._secrets[key]
        except KeyError as exc:  # pragma: no cover - defensive guard
            raise LookupError(f"Secret {key} not found") from exc


__all__ = ["FakeConnection", "FakePool", "FakeResult", "StaticSecretResolver"]
