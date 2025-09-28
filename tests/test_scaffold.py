from __future__ import annotations

import pytest

from mere import scaffold


def _options(
    *,
    name: str = "Demo Service",
    git_host: str = "github",
    iac: str = "terraform",
    backbone: str = "aws",
    include_dev_stack: bool = True,
) -> scaffold.ProjectOptions:
    return scaffold.ProjectOptions(
        name=name,
        git_host=git_host,  # type: ignore[arg-type]
        iac=iac,  # type: ignore[arg-type]
        backbone=backbone,  # type: ignore[arg-type]
        include_dev_stack=include_dev_stack,
    )


def test_render_project_generates_expected_core_files() -> None:
    summary = scaffold.render_project(_options())
    paths = {file.path for file in summary.files}
    assert ".env.example" in paths
    assert "app/application.py" in paths
    assert "infra/terraform/main.tf" in paths
    assert "ops/docker-compose.yml" in paths

    pyproject = next(file for file in summary.files if file.path == "pyproject.toml")
    assert 'name = "demo_service"' in pyproject.content


def test_render_project_without_dev_stack() -> None:
    summary = scaffold.render_project(_options(include_dev_stack=False))
    paths = {file.path for file in summary.files}
    assert "ops/docker-compose.yml" not in paths


@pytest.mark.parametrize(
    "iac, expected",
    [
        ("terraform", 'module "mere"'),
        ("opentofu", "tofu"),
        ("k8s", "apiVersion: apps/v1"),
        ("cfn", "AWS::ECS::Service"),
    ],
)
def test_render_project_various_iac(iac: str, expected: str) -> None:
    summary = scaffold.render_project(_options(iac=iac))
    content = "\n".join(file.content for file in summary.files if file.path.startswith("infra/"))
    assert expected in content


def test_render_project_respects_backbone_labels() -> None:
    summary = scaffold.render_project(_options(backbone="gcp"))
    readme = next(file for file in summary.files if file.path == "README.md")
    assert "Google Cloud Platform" in readme.content


def test_terraform_provider_blocks_cover_all_backbones() -> None:
    providers = {
        "aws": scaffold._terraform_provider_block("aws"),
        "gcp": scaffold._terraform_provider_block("gcp"),
        "azure": scaffold._terraform_provider_block("azure"),
        "digitalocean": scaffold._terraform_provider_block("digitalocean"),
        "cloudflare": scaffold._terraform_provider_block("cloudflare"),
    }
    assert "hashicorp/aws" in providers["aws"].required_provider
    assert 'provider "google"' in providers["gcp"].provider_block
    assert "features {}" in providers["azure"].provider_block
    assert providers["digitalocean"].provider_block == 'provider "digitalocean" {}'
    assert "api_token" in providers["cloudflare"].provider_block


def test_cfn_templates_use_backbone_label() -> None:
    template = scaffold._cfn_template(_options(backbone="digitalocean"), "demo")
    readme = scaffold._cfn_readme(_options(backbone="digitalocean"))
    assert "DigitalOcean" in template
    assert "DigitalOcean" in readme


def test_compose_and_ops_templates() -> None:
    compose = scaffold._compose_template()
    ops = scaffold._ops_readme_template()
    assert "postgres" in compose
    assert "docker compose" in ops
