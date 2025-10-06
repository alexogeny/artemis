# Mere

## Developer bootstrap

Mere ships with a developer bootstrap that wires production-grade authentication and tenancy scaffolding for a
multi-tenant deployment whenever you instantiate `MereApp` with `bootstrap_enabled=True`. The helper defaults to development/staging
domains so the sample tenants (`acme`, `beta`) stay out of production, but the login engine and routes it
exposes are the same ones you would run for real customers. Configuration is driven entirely through
environment variables so each developer can point the bootstrap at tenant data that matches their sandbox.
Copy `.env.example` to `.env`, adjust the payload, and run local services with `uv run --env-file .env <command>`
(or export the variables directly in your shell). When enabled it provides:

The repository ships with [`example.py`](example.py) so you can kick the tyres immediately:

```bash
uv sync
uv run example.py
```

The script starts a Granian server with the bootstrap bundle already wired in. Override `MERE_SITE`,
`MERE_DOMAIN`, `MERE_ALLOWED_TENANTS`, `MERE_HOST`, or `MERE_PORT` to tailor the tenancy hostnames and bind
address. Provide a `DATABASE_URL` when you want the bootstrap tables to persist in PostgreSQL; otherwise the
demo operates purely in memory.

* **Diagnostics:** `/__mere/ping`, OpenAPI JSON, and a generated TypeScript client that all resolve for
  every tenant host (`*.site.domain`), including the admin control plane (`admin.site.domain`).
* **Authentication flows:** fully tenant-aware login endpoints that model SSO, passkey, password, and MFA
  hops for both customer tenants and the admin realm—the same orchestration used in production Mere
  deployments. The default configuration ships with:
  * `acme.<site>.<domain>` → SAML SSO metadata wired for Okta.
  * `beta.<site>.<domain>` → passkey-first flow with password fallback plus TOTP-style MFA.
  * `admin.<site>.<domain>` → password + MFA guardrails for administrators.
* **Tenant registry sync:** when a database is attached the bootstrap helper keeps
  `app.tenant_resolver.allowed_tenants` aligned with the `bootstrap_tenants` table in the admin schema so new
  subdomains start resolving as soon as they exist in the registry.
* **Database bootstrap:** admin and tenant tables (`bootstrap_tenants`, `bootstrap_admin_users`,
  `bootstrap_users`) created through `bootstrap_migrations()` and populated by `BootstrapSeeder` so you
  can poke at real rows with SQL or the ORM. The seeder records a fingerprint of the applied config in
  `bootstrap_seed_state`, so restarts skip destructive re-seeding unless the configuration changes.

### Endpoints

When enabled, all routes live under `/__mere` by default (configurable via `base_path`).

| Method | Path                          | Description                                      |
| ------ | ----------------------------- | ------------------------------------------------ |
| GET    | `/ping`                       | Tenant-aware health probe.                       |
| GET    | `/openapi.json`               | Generated OpenAPI document.                      |
| GET    | `/client.ts`                  | Ready-to-use TypeScript SDK.                     |
| POST   | `/auth/login/start`           | Begin login (returns SSO/passkey/password hints).|
| POST   | `/auth/login/passkey`         | Complete a passkey assertion.                    |
| POST   | `/auth/login/password`        | Submit a password (handles passkey fallbacks).   |
| POST   | `/auth/login/mfa`             | Finish MFA challenges and receive a reference session.|

### Documentation

The documentation lives in the [`docs/`](docs/) directory and is rendered with MkDocs using the
`mkdocs-shadcn` theme. Preview changes locally with `uv run mkdocs serve`. Pushes to `main` publish the
site automatically through the GitHub Pages workflow; trigger a manual deploy with `uv run mkdocs gh-deploy --force`
when needed.

## CLI project generator

Create a production-ready Mere service, complete with bootstrap wiring, IaC skeletons, and local
Compose tooling, using the bundled CLI:

```bash
uv run mere new my-service --git-host github --iac terraform --backbone aws
```

The generator can target GitHub or GitLab CI, multiple IaC providers (Terraform, OpenTofu, Kubernetes,
CloudFormation), and backbone clouds (AWS, DigitalOcean, Cloudflare, Google Cloud, Azure). Use
`--skip-dev-stack` if you do not need the Docker Compose PostgreSQL/Keycloak development environment.
Run `uv run mere new --help` to inspect the full matrix of options at any time.

### Database bootstrap

When the app exposes a `Database` and `ORM`, the bootstrap helper automatically runs
`bootstrap_migrations()` to materialise the admin (`bootstrap_tenants`, `bootstrap_admin_users`) and
tenant (`bootstrap_users`) tables and seeds them with reference data via `BootstrapSeeder`. You can inspect the
rows with the ORM or raw SQL and even hydrate the in-memory config again using `BootstrapRepository.load()`:

```python
tenants = await app.orm.admin.bootstrap_tenants.list()
beta_ctx = app.tenant_resolver.context_for("beta")
beta_users = await app.orm.tenants.bootstrap_users.list(tenant=beta_ctx)

repository = BootstrapRepository(app.orm, site=app.config.site, domain=app.config.domain)
config = await repository.load()
```

### Customising the seed data

Pass a `BootstrapAuthConfig` into `MereApp(…, bootstrap_auth=…)` to model your own tenants, users, and
credentials. When a database is attached the seeder writes those identities into the bootstrap tables so you
can iterate with realistic storage. Construct `MereApp` with a `Database`/`ORM` to persist the data, or omit
them to stay purely in-memory. You can also point the bootstrap at configuration stored in environment
variables. The helper first checks `MERE_BOOTSTRAP_AUTH_FILE` (pointing to a JSON file) and then `MERE_BOOTSTRAP_AUTH`
(inline JSON). The `.env.example` file documents both options so teams can either mount secrets from their
manager into files or export them inline. The loader resolves `_FILE` first so you can keep real credentials
outside the repository.

Example using inline configuration:

```python
from mere import AppConfig, MereApp
from mere.bootstrap import (
    DEFAULT_BOOTSTRAP_AUTH,
    BootstrapAuthConfig,
    BootstrapPasskey,
    BootstrapTenant,
    BootstrapUser,
)

auth_config = BootstrapAuthConfig(
    tenants=(
        BootstrapTenant(
            slug="acme",
            name="Acme Rockets",
            users=(
                BootstrapUser(
                    id="usr_acme_owner",
                    email="founder@acme.test",
                    password="founder-pass",
                    passkeys=(BootstrapPasskey(credential_id="key-1", secret="founder-secret"),),
                    mfa_code="654321",
                ),
            ),
        ),
    ),
    admin=DEFAULT_BOOTSTRAP_AUTH.admin,
)

app = MereApp(
    AppConfig(site="demo", domain="local.test", allowed_tenants=("acme",)),
    bootstrap_auth=auth_config,
)
```

### SAML provider configuration

Mere validates SAML assertions by honoring both the `<Conditions>` and `<SubjectConfirmationData>`
timestamps inside each assertion. Providers can tune that behavior on `TenantSamlProvider`:

* `clock_skew_seconds` (default: 120) expands the acceptance window on both sides when comparing the
  `NotBefore` and `NotOnOrAfter` attributes. Increase this value when your identity provider's clock runs
  slightly ahead or behind your cluster to avoid spurious `assertion_not_yet_valid` or `assertion_expired`
  errors.
* `allowed_audiences` enumerates the `<Audience>` values that Mere will accept. When populated, at least
  one audience in the assertion must match the configured list, otherwise validation fails with
  `invalid_audience`. Leave the list empty to accept any audience from the identity provider.

All comparison happens in UTC; assertions that use a trailing `Z` or explicit `+00:00` offsets are accepted.
