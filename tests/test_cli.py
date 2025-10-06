from __future__ import annotations

import pathlib
from types import SimpleNamespace
from typing import Sequence

import pytest

import mere.cli as cli
from mere.scaffold import ProjectFile, ProjectOptions, ProjectSummary


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


def test_new_project_scaffolds_files(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "demo-service"
    result = cli.main(
        [
            "new",
            str(target),
            "--git-host",
            "github",
            "--iac",
            "terraform",
            "--backbone",
            "aws",
        ]
    )
    assert result == 0

    readme = (target / "README.md").read_text(encoding="utf-8")
    assert "AWS" in readme

    app_module = (target / "app/application.py").read_text(encoding="utf-8")
    assert "MereApp(" in app_module

    workflow = (target / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "uv run pytest" in workflow

    compose = (target / "ops/docker-compose.yml").read_text(encoding="utf-8")
    assert "postgres:16-alpine" in compose

    terraform = (target / "infra/terraform/main.tf").read_text(encoding="utf-8")
    assert 'provider "aws"' in terraform


def test_new_project_gitlab_k8s_without_dev_stack(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "demo"
    result = cli.main(
        [
            "new",
            str(target),
            "--git-host",
            "gitlab",
            "--iac",
            "k8s",
            "--backbone",
            "gcp",
            "--skip-dev-stack",
        ]
    )
    assert result == 0

    assert (target / ".gitlab-ci.yml").exists()
    assert not (target / "ops/docker-compose.yml").exists()

    deployment = (target / "infra/k8s/deployment.yaml").read_text(encoding="utf-8")
    assert "namespace: demo" in deployment


def test_new_project_rejects_non_empty_target(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "demo"
    target.mkdir()
    (target / "README.md").write_text("existing", encoding="utf-8")

    with pytest.raises(SystemExit):
        cli.main(["new", str(target)])


def test_new_project_rejects_file_target(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "demo"
    path.write_text("file", encoding="utf-8")

    with pytest.raises(SystemExit):
        cli.main(["new", str(path)])


def test_new_project_rejects_overwrite(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "demo"
    target.mkdir()

    def fake_render_project(options: ProjectOptions) -> ProjectSummary:
        existing = target / ".env.example"
        existing.write_text("preexisting", encoding="utf-8")
        return ProjectSummary(files=(ProjectFile(path=".env.example", content="data"),))

    monkeypatch.setattr(cli, "render_project", fake_render_project)

    with pytest.raises(SystemExit):
        cli.main(["new", str(target)])
