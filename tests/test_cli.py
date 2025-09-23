from __future__ import annotations

from types import SimpleNamespace
from typing import Sequence

import pytest

import artemis.cli as cli


def test_quality_runs_all_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(command: Sequence[str], *, check: bool = False) -> SimpleNamespace:
        calls.append(tuple(command))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.quality() == 0
    assert calls == [tuple(step) for step in cli.QUALITY_COMMANDS]


def test_quality_stops_on_first_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(command: Sequence[str], *, check: bool = False) -> SimpleNamespace:
        calls.append(tuple(command))
        if command[0] == "ty":
            return SimpleNamespace(returncode=2)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.quality() == 2
    assert calls == [tuple(cli.QUALITY_COMMANDS[0]), tuple(cli.QUALITY_COMMANDS[1])]
