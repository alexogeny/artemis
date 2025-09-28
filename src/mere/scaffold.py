"""Project scaffolding helpers for Mere."""

from __future__ import annotations

from textwrap import dedent
from typing import Final, Iterable, Literal

from msgspec import Struct

GIT_HOSTS: Final[tuple[str, ...]] = ("github", "gitlab")
IAC_PROVIDERS: Final[tuple[str, ...]] = ("terraform", "opentofu", "k8s", "cfn")
BACKBONES: Final[tuple[str, ...]] = ("aws", "digitalocean", "cloudflare", "gcp", "azure")


class ProjectOptions(Struct, frozen=True):
    """Declarative inputs for project scaffolding."""

    name: str
    git_host: Literal["github", "gitlab"]
    iac: Literal["terraform", "opentofu", "k8s", "cfn"]
    backbone: Literal["aws", "digitalocean", "cloudflare", "gcp", "azure"]
    include_dev_stack: bool = True


class ProjectFile(Struct, frozen=True):
    """Materialised file produced during scaffolding."""

    path: str
    content: str


class ProjectSummary(Struct, frozen=True):
    """Result of rendering a project template."""

    files: tuple[ProjectFile, ...]


def render_project(options: ProjectOptions) -> ProjectSummary:
    """Render a production-ready Mere project based on ``options``."""

    slug = _normalize_package(options.name)
    title = _title_case(options.name)
    files: list[ProjectFile] = []

    files.extend(_core_files(options, slug, title))
    files.extend(_ci_files(options))
    files.extend(_iac_files(options, slug))

    if options.include_dev_stack:
        files.extend(_dev_stack_files())

    return ProjectSummary(files=tuple(files))


def _core_files(options: ProjectOptions, slug: str, title: str) -> Iterable[ProjectFile]:
    env = _env_template()
    gitignore = _gitignore_template()
    readme = _readme_template(options, title)
    pyproject = _pyproject_template(slug)
    app_module = _app_template()
    runtime_module = _runtime_template()
    main_module = _main_module_template()
    return (
        ProjectFile(path=".env.example", content=env),
        ProjectFile(path=".gitignore", content=gitignore),
        ProjectFile(path="README.md", content=readme),
        ProjectFile(path="pyproject.toml", content=pyproject),
        ProjectFile(path="app/__init__.py", content=""),
        ProjectFile(path="app/application.py", content=app_module),
        ProjectFile(path="app/runtime.py", content=runtime_module),
        ProjectFile(path="app/__main__.py", content=main_module),
    )


def _ci_files(options: ProjectOptions) -> Iterable[ProjectFile]:
    if options.git_host == "github":
        workflow = _github_ci_template()
        return (ProjectFile(path=".github/workflows/ci.yml", content=workflow),)
    workflow = _gitlab_ci_template()
    return (ProjectFile(path=".gitlab-ci.yml", content=workflow),)


def _iac_files(options: ProjectOptions, slug: str) -> Iterable[ProjectFile]:
    if options.iac in {"terraform", "opentofu"}:
        return (
            ProjectFile(path=f"infra/{options.iac}/main.tf", content=_terraform_template(options)),
            ProjectFile(path=f"infra/{options.iac}/variables.tf", content=_terraform_variables_template()),
            ProjectFile(path=f"infra/{options.iac}/README.md", content=_terraform_readme_template(options)),
        )
    if options.iac == "k8s":
        return (
            ProjectFile(path="infra/k8s/namespace.yaml", content=_k8s_namespace_template(slug)),
            ProjectFile(path="infra/k8s/deployment.yaml", content=_k8s_deployment_template(slug)),
            ProjectFile(path="infra/k8s/service.yaml", content=_k8s_service_template(slug)),
            ProjectFile(path="infra/k8s/ingress.yaml", content=_k8s_ingress_template(options, slug)),
        )
    return (
        ProjectFile(path="infra/cfn/template.yaml", content=_cfn_template(options, slug)),
        ProjectFile(path="infra/cfn/README.md", content=_cfn_readme(options)),
    )


def _dev_stack_files() -> Iterable[ProjectFile]:
    compose = _compose_template()
    ops_readme = _ops_readme_template()
    return (
        ProjectFile(path="ops/docker-compose.yml", content=compose),
        ProjectFile(path="ops/README.md", content=ops_readme),
        ProjectFile(path="ops/migrations/.keep", content=""),
    )


def _env_template() -> str:
    return dedent(
        """\
        MERE_ENV=development
        MERE_SITE=demo
        MERE_DOMAIN=local.test
        MERE_ALLOWED_TENANTS=acme,beta
        DATABASE_URL=postgresql://mere:mere@localhost:5432/mere
        SLACK_WEBHOOK_URL=http://localhost:9090/mock-slack
        """
    )


def _gitignore_template() -> str:
    return dedent(
        """\
        __pycache__/
        *.py[cod]
        .env
        .venv/
        .mypy_cache/
        .pytest_cache/
        .uv/
        ops/postgres-data/
        ops/keycloak-data/
        infra/**/.terraform/
        infra/**/.terraform.lock.hcl
        """
    )


def _readme_template(options: ProjectOptions, title: str) -> str:
    git_label = options.git_host.title()
    backbone = _backbone_label(options.backbone)
    if options.iac == "k8s":
        iac_label = "Kubernetes"
    else:
        iac_label = options.iac.upper()
    return (
        dedent(
            f"""\
        # {title}

        Production-ready Mere deployment scaffolded for {backbone} with {iac_label}.

        ## Stack

        - Git host: {git_label}
        - Infrastructure as Code: {iac_label}
        - Backbone provider: {backbone}
        - Local services: Docker Compose (PostgreSQL 16 + Keycloak 23)

        ## Getting started

        ```bash
        uv sync
        cp .env.example .env
        docker compose -f ops/docker-compose.yml up --detach
        uv run mere migrate --module app.runtime
        uv run python -m app
        ```

        ## Project layout

        - `app/` - ASGI application wiring and route registration.
        - `infra/` - IaC definitions for the selected backbone.
        - `ops/` - Local developer tooling (Compose stack, seed data).
        - CI configuration for the chosen git host.

        This scaffold boots with the Mere quickstart so your local environment matches
        the production authentication and tenancy flows. Adjust the seed data in
        `app/runtime.py` before promoting tenants to real customers.
        """
        ).strip()
        + "\n"
    )


def _pyproject_template(package: str) -> str:
    script = package.replace("_", "-")
    return dedent(
        f"""\
        [project]
        name = "{package}"
        version = "0.1.0"
        description = "Production Mere service"
        requires-python = ">=3.11"
        dependencies = [
            "mere",
        ]

        [tool.uv]
        package = false

        [project.scripts]
        {script} = "app.application:main"
        """
    )


def _app_template() -> str:
    return (
        dedent(
            """\
        from __future__ import annotations

        import os

        from mere import AppConfig, MereApp, attach_quickstart
        from mere.database import DatabaseConfig, PoolConfig
        from mere.requests import Request
        from mere.responses import JSONResponse
        from mere.server import run


        def _allowed_tenants() -> tuple[str, ...]:
            raw = os.getenv("MERE_ALLOWED_TENANTS", "acme,beta")
            return tuple(sorted({tenant.strip() for tenant in raw.split(",") if tenant.strip()}))


        def create_app() -> MereApp:
            config = AppConfig(
                site=os.getenv("MERE_SITE", "demo"),
                domain=os.getenv("MERE_DOMAIN", "local.test"),
                allowed_tenants=_allowed_tenants(),
                database=DatabaseConfig(
                    pool=PoolConfig(dsn=os.getenv("DATABASE_URL", "postgresql://mere:mere@localhost:5432/mere"))
                ),
            )
            app = MereApp(config)
            attach_quickstart(app)

            @app.get("/health", name="health")
            async def health(_: Request) -> JSONResponse:
                return JSONResponse({"status": "ok"})

            return app


        def main() -> None:
            app = create_app()
            run(app)
        """
        ).strip()
        + "\n"
    )


def _runtime_template() -> str:
    return (
        dedent(
            """\
        from __future__ import annotations

        import os

        from mere import AppConfig
        from mere.database import Database, DatabaseConfig, PoolConfig
        from mere.tenancy import TenantContext, TenantScope


        def _parse_tenants() -> tuple[str, ...]:
            raw = os.getenv("MERE_ALLOWED_TENANTS", "acme,beta")
            return tuple(sorted({tenant.strip() for tenant in raw.split(",") if tenant.strip()}))


        def build_config() -> AppConfig:
            allowed = _parse_tenants()
            database_url = os.getenv("DATABASE_URL")
            database_config: DatabaseConfig | None = None
            if database_url:
                database_config = DatabaseConfig(pool=PoolConfig(dsn=database_url))
            return AppConfig(
                site=os.getenv("MERE_SITE", "demo"),
                domain=os.getenv("MERE_DOMAIN", "local.test"),
                allowed_tenants=allowed,
                database=database_config,
            )


        def get_database() -> Database:
            config = build_config()
            if config.database is None:
                raise RuntimeError("DATABASE_URL must be configured to run migrations")
            return Database(config.database)


        def get_tenants() -> tuple[TenantContext, ...]:
            config = build_config()
            tenants: list[TenantContext] = []
            for slug in config.allowed_tenants:
                tenants.append(
                    TenantContext(
                        tenant=slug,
                        site=config.site,
                        domain=config.domain,
                        scope=TenantScope.TENANT,
                    )
                )
            return tuple(tenants)
        """
        ).strip()
        + "\n"
    )


def _main_module_template() -> str:
    return (
        dedent(
            """\
        from .application import main


        if __name__ == "__main__":
            main()
        """
        ).strip()
        + "\n"
    )


def _github_ci_template() -> str:
    return dedent(
        """\
        name: CI

        on:
          push:
            branches: [main]
          pull_request:

        jobs:
          quality:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: astral-sh/setup-uv@v2
              - run: uv sync
              - run: uv run ruff check
              - run: uv run ty check
              - run: uv run pytest
        """
    )


def _gitlab_ci_template() -> str:
    return dedent(
        """\
        stages:
          - quality

        quality:
          stage: quality
          image: ghcr.io/astral-sh/uv:latest
          script:
            - uv sync
            - uv run ruff check
            - uv run ty check
            - uv run pytest
        """
    )


def _terraform_template(options: ProjectOptions) -> str:
    provider = _terraform_provider_block(options.backbone)
    tool = "tofu" if options.iac == "opentofu" else "terraform"
    body = dedent(
        f"""\
        {tool} {{
          required_version = ">= 1.5.0"
          required_providers {{
{provider.required_provider}
          }}
        }}

{provider.provider_block}

        module "mere" {{
          source = "./modules/mere"
          site   = var.site
          domain = var.domain
        }}
        """
    )
    return body.strip() + "\n"


def _terraform_variables_template() -> str:
    return dedent(
        """\
        variable "site" {
          type        = string
          description = "Mere site identifier"
        }

        variable "domain" {
          type        = string
          description = "Base domain for tenant routing"
        }
        """
    )


def _terraform_readme_template(options: ProjectOptions) -> str:
    tool = "OpenTofu" if options.iac == "opentofu" else "Terraform"
    provider = _backbone_label(options.backbone)
    return dedent(
        f"""\
        # {tool} deployment

        Apply the Mere infrastructure stack on {provider}:

        ```bash
        {tool.lower()} init
        {tool.lower()} apply
        ```

        Populate `terraform.tfvars` with values for the variables declared in `variables.tf`.
        """
    )


def _k8s_namespace_template(package: str) -> str:
    return dedent(
        f"""\
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {package}
        """
    )


def _k8s_deployment_template(package: str) -> str:
    return dedent(
        f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {package}-web
          namespace: {package}
        spec:
          replicas: 2
          selector:
            matchLabels:
              app: {package}-web
          template:
            metadata:
              labels:
                app: {package}-web
            spec:
              containers:
                - name: mere
                  image: ghcr.io/your-org/{package}:latest
                  env:
                    - name: MERE_ENV
                      value: production
                    - name: DATABASE_URL
                      valueFrom:
                        secretKeyRef:
                          name: {package}-database
                          key: url
                  ports:
                    - containerPort: 8000
        """
    )


def _k8s_service_template(package: str) -> str:
    return dedent(
        f"""\
        apiVersion: v1
        kind: Service
        metadata:
          name: {package}-web
          namespace: {package}
        spec:
          selector:
            app: {package}-web
          ports:
            - port: 80
              targetPort: 8000
        """
    )


def _k8s_ingress_template(options: ProjectOptions, package: str) -> str:
    backbone = _backbone_label(options.backbone)
    return dedent(
        f"""\
        apiVersion: networking.k8s.io/v1
        kind: Ingress
        metadata:
          name: {package}-ingress
          namespace: {package}
          annotations:
            meta.mere.dev/backbone: "{backbone}"
        spec:
          rules:
            - host: api.{package}.example.com
              http:
                paths:
                  - path: /
                    pathType: Prefix
                    backend:
                      service:
                        name: {package}-web
                        port:
                          number: 80
        """
    )


def _cfn_template(options: ProjectOptions, package: str) -> str:
    provider = _backbone_label(options.backbone)
    return dedent(
        f"""\
        AWSTemplateFormatVersion: '2010-09-09'
        Description: Mere service for {provider}
        Resources:
          MereService:
            Type: AWS::ECS::Service
            Properties:
              Cluster: !Ref MereCluster
              DesiredCount: 2
              LaunchType: FARGATE
              ServiceName: {package}-service
              TaskDefinition: !Ref MereTaskDefinition
          MereCluster:
            Type: AWS::ECS::Cluster
          MereTaskDefinition:
            Type: AWS::ECS::TaskDefinition
            Properties:
              Cpu: '512'
              Memory: '1024'
              NetworkMode: awsvpc
              RequiresCompatibilities:
                - FARGATE
              ContainerDefinitions:
                - Name: mere
                  Image: public.ecr.aws/your-org/{package}:latest
                  PortMappings:
                    - ContainerPort: 8000
                  Environment:
                    - Name: MERE_ENV
                      Value: production
                    - Name: DATABASE_URL
                      Value: {{resolve:secretsmanager:{package}/database:SecretString:url}}
        """
    )


def _cfn_readme(options: ProjectOptions) -> str:
    provider = _backbone_label(options.backbone)
    return dedent(
        f"""\
        # CloudFormation deployment

        Deploy the stack on {provider}:

        ```bash
        aws cloudformation deploy \\
          --template-file template.yaml \\
          --stack-name mere-stack \\
          --capabilities CAPABILITY_NAMED_IAM
        ```

        Parameterise the template before deploying to production environments.
        """
    )


def _compose_template() -> str:
    return dedent(
        """\
        version: '3.9'

        services:
          postgres:
            image: postgres:16-alpine
            ports:
              - "5432:5432"
            environment:
              POSTGRES_DB: mere
              POSTGRES_USER: mere
              POSTGRES_PASSWORD: mere
            volumes:
              - ./postgres-data:/var/lib/postgresql/data

          keycloak:
            image: quay.io/keycloak/keycloak:23.0
            command:
              - start-dev
              - --http-port=8081
            environment:
              KC_DB: postgres
              KC_DB_URL: jdbc:postgresql://postgres:5432/mere
              KC_DB_USERNAME: mere
              KC_DB_PASSWORD: mere
              KEYCLOAK_ADMIN: admin
              KEYCLOAK_ADMIN_PASSWORD: admin
            ports:
              - "8081:8080"
            depends_on:
              - postgres
            volumes:
              - ./keycloak-data:/opt/keycloak/data
        """
    )


def _ops_readme_template() -> str:
    return dedent(
        """\
        # Developer operations

        ```bash
        # Start PostgreSQL and Keycloak
        docker compose -f ops/docker-compose.yml up --detach

        # Tear them down
        docker compose -f ops/docker-compose.yml down --volumes
        ```
        """
    )


class _TerraformProvider(Struct, frozen=True):
    required_provider: str
    provider_block: str


def _terraform_provider_block(backbone: str) -> _TerraformProvider:
    if backbone == "aws":
        return _TerraformProvider(
            required_provider=dedent(
                """\
                    aws = {
                      source  = \"hashicorp/aws\"
                      version = \"~> 5.0\"
                    }
                """
            ).strip(),
            provider_block=dedent(
                """\
                provider \"aws\" {
                  region = var.region
                }
                """
            ).strip(),
        )
    if backbone == "gcp":
        return _TerraformProvider(
            required_provider=dedent(
                """\
                    google = {
                      source  = \"hashicorp/google\"
                      version = \"~> 5.0\"
                    }
                """
            ).strip(),
            provider_block=dedent(
                """\
                provider \"google\" {
                  project = var.project
                  region  = var.region
                }
                """
            ).strip(),
        )
    if backbone == "azure":
        return _TerraformProvider(
            required_provider=dedent(
                """\
                    azurerm = {
                      source  = \"hashicorp/azurerm\"
                      version = \"~> 3.0\"
                    }
                """
            ).strip(),
            provider_block=dedent(
                """\
                provider \"azurerm\" {
                  features {}
                }
                """
            ).strip(),
        )
    if backbone == "digitalocean":
        return _TerraformProvider(
            required_provider=dedent(
                """\
                    digitalocean = {
                      source  = \"digitalocean/digitalocean\"
                      version = \"~> 2.0\"
                    }
                """
            ).strip(),
            provider_block='provider "digitalocean" {}',
        )
    return _TerraformProvider(
        required_provider=dedent(
            """\
                cloudflare = {
                  source  = \"cloudflare/cloudflare\"
                  version = \"~> 4.0\"
                }
            """
        ).strip(),
        provider_block=dedent(
            """\
            provider \"cloudflare\" {
              api_token = var.api_token
            }
            """
        ).strip(),
    )


def _backbone_label(backbone: str) -> str:
    mapping = {
        "aws": "AWS",
        "digitalocean": "DigitalOcean",
        "cloudflare": "Cloudflare",
        "gcp": "Google Cloud Platform",
        "azure": "Microsoft Azure",
    }
    return mapping.get(backbone, backbone.title())


def _normalize_package(name: str) -> str:
    cleaned = [ch if ch.isalnum() else "_" for ch in name.lower()]
    slug = "".join(cleaned).strip("_")
    return slug or "mere_service"


def _title_case(name: str) -> str:
    parts = [part for part in name.replace("-", " ").replace("_", " ").split() if part]
    return " ".join(part.capitalize() for part in parts) or "Mere Service"


__all__ = [
    "BACKBONES",
    "GIT_HOSTS",
    "IAC_PROVIDERS",
    "ProjectFile",
    "ProjectOptions",
    "ProjectSummary",
    "render_project",
]
