# Bootstrap helper

Mere ships with a developer bootstrap that seeds a ready-to-use login experience, sample tenants, and
supporting routes under `/__mere`. It is ideal for demos, smoke tests, and early development stages.

## Enabling the bootstrap

```python
from mere import AppConfig, MereApp

config = AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta"))
app = MereApp(config)
```

Instantiating `MereApp` automatically registers the bootstrap routes, configures tenancy metadata, and
loads the embedded front-end assets. Set `bootstrap_enabled=False` when you need to skip the wiring and
call `attach_bootstrap` manually (useful in tests where you monkeypatch the bootstrap internals).

## Scaffolding a production project

The `mere` CLI can materialise a complete project—including tenancy-aware bootstrap wiring,
infrastructure definitions, and local developer tooling—in a single command:

```bash
uv run mere new my-service \
  --git-host github \
  --iac terraform \
  --backbone aws
```

The generator creates:

- `app/` with a ready-to-serve `MereApp` that already exposes the bootstrap wiring and a `/health` probe.
- `app/runtime.py` exposing `get_database()`/`get_tenants()` so migrations and test data snapshots work
  out of the box.
- CI workflows tailored to GitHub or GitLab with the full `ruff`/`ty`/`pytest` quality bar.
- IaC skeletons for Terraform/OpenTofu, Kubernetes, or CloudFormation preconfigured for AWS,
  Google Cloud, Azure, DigitalOcean, or Cloudflare.
- `ops/docker-compose.yml` to launch PostgreSQL 16 and Keycloak 23 locally, matching the bootstrap
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

When a database connection is supplied through `AppConfig`, the bootstrap helper provisions schemas
and seed data via `bootstrap_migrations()` and `BootstrapSeeder`. The helper keeps the
`TenantResolver.allowed_tenants` list in sync with the database, so new tenants appear as soon as they
are registered.
