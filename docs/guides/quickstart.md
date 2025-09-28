# Quickstart helper

The `attach_quickstart` function seeds a ready-to-use login experience, sample tenants, and supporting
routes that live under `/__mere`. It is ideal for demos, smoke tests, and early development stages.

## Enabling the quickstart

```python
from mere import AppConfig, MereApp
from mere.quickstart import attach_quickstart

config = AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta"))
app = MereApp(config)
attach_quickstart(app)
```

Calling `attach_quickstart` registers routes, configures tenancy metadata, and loads the embedded
front-end assets. The helper is idempotent—calling it multiple times inspects the existing state and
only applies missing pieces.

## Scaffolding a production project

The `mere` CLI can materialise a complete project—including tenancy-aware quickstart wiring,
infrastructure definitions, and local developer tooling—in a single command:

```bash
uv run mere new my-service \
  --git-host github \
  --iac terraform \
  --backbone aws
```

The generator creates:

- `app/` with a ready-to-serve `MereApp` that calls `attach_quickstart` and exposes a `/health` probe.
- `app/runtime.py` exposing `get_database()`/`get_tenants()` so migrations and test data snapshots work
  out of the box.
- CI workflows tailored to GitHub or GitLab with the full `ruff`/`ty`/`pytest` quality bar.
- IaC skeletons for Terraform/OpenTofu, Kubernetes, or CloudFormation preconfigured for AWS,
  Google Cloud, Azure, DigitalOcean, or Cloudflare.
- `ops/docker-compose.yml` to launch PostgreSQL 16 and Keycloak 23 locally, matching the quickstart
  authentication flows.

Use `--skip-dev-stack` to omit the Docker Compose files if your team relies on an alternative local
stack, and swap `--iac`/`--backbone`/`--git-host` to match your production environment. Consult
`uv run mere new --help` whenever you need a refresher on the supported combinations.

## Authentication flows

- **Acme tenant** – configured for SAML SSO with Okta metadata. Use it to validate SSO login logic.
- **Beta tenant** – demonstrates passkeys with password fallback and TOTP-based MFA.
- **Admin realm** – enforces password + MFA to protect administrative APIs.

Each flow uses the same orchestration as production deployments so you can test the complete session
lifecycle end to end.

## Database bootstrap

When a database connection is supplied through `AppConfig`, the quickstart helper provisions schemas
and seed data via `quickstart_migrations()` and `QuickstartSeeder`. The helper keeps the
`TenantResolver.allowed_tenants` list in sync with the database, so new tenants appear as soon as they
are registered.
