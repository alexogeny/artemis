# Mere

## Developer quickstart

`attach_quickstart` wires production-grade authentication and tenancy scaffolding for a multi-tenant Mere
deployment in a few lines of code. The helper defaults to development/staging domains so the sample tenants
(`acme`, `beta`) stay out of production, but the login engine and routes it exposes are the same ones you would
run for real customers. Configuration is driven entirely through environment variables so each developer can
point the quickstart at tenant data that matches their sandbox. Copy `.env.example` to `.env`, adjust the
payload, and run local services with `uv run --env-file .env <command>` (or export the variables directly in
your shell). When enabled it provides:

* **Diagnostics:** `/__mere/ping`, OpenAPI JSON, and a generated TypeScript client that all resolve for
  every tenant host (`*.site.domain`), including the admin control plane (`admin.site.domain`).
* **Authentication flows:** fully tenant-aware login endpoints that model SSO, passkey, password, and MFA
  hops for both customer tenants and the admin realm—the same orchestration used in production Mere
  deployments. The default configuration ships with:
  * `acme.<site>.<domain>` → SAML SSO metadata wired for Okta.
  * `beta.<site>.<domain>` → passkey-first flow with password fallback plus TOTP-style MFA.
  * `admin.<site>.<domain>` → password + MFA guardrails for administrators.
* **Tenant registry sync:** when a database is attached the quickstart helper keeps
  `app.tenant_resolver.allowed_tenants` aligned with the `quickstart_tenants` table in the admin schema so new
  subdomains start resolving as soon as they exist in the registry.
* **Database bootstrap:** admin and tenant tables (`quickstart_tenants`, `quickstart_admin_users`,
  `quickstart_users`) created through `quickstart_migrations()` and populated by `QuickstartSeeder` so you
  can poke at real rows with SQL or the ORM. The seeder records a fingerprint of the applied config in
  `quickstart_seed_state`, so restarts skip destructive re-seeding unless the configuration changes.

### Endpoints

All routes live under `/__mere` by default (configurable via `base_path`).

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
`mkdocs-shadcn` theme. Preview changes locally with `uv run mkdocs serve` and publish to GitHub Pages
via `uv run mkdocs gh-deploy --force`.

### Database bootstrap

When the app exposes a `Database` and `ORM`, the quickstart helper automatically runs
`quickstart_migrations()` to materialise the admin (`quickstart_tenants`, `quickstart_admin_users`) and
tenant (`quickstart_users`) tables and seeds them with reference data via `QuickstartSeeder`. You can inspect the
rows with the ORM or raw SQL and even hydrate the in-memory config again using `QuickstartRepository.load()`:

```python
tenants = await app.orm.admin.quickstart_tenants.list()
beta_ctx = app.tenant_resolver.context_for("beta")
beta_users = await app.orm.tenants.quickstart_users.list(tenant=beta_ctx)

repository = QuickstartRepository(app.orm, site=app.config.site, domain=app.config.domain)
config = await repository.load()
```

### Customising the seed data

Pass a `QuickstartAuthConfig` into `attach_quickstart` to model your own tenants, users, and credentials.
When a database is attached the seeder writes those identities into the quickstart tables so you can iterate
with realistic storage. Construct `MereApp` with a `Database`/`ORM` to persist the data, or omit them to stay
purely in-memory. You can also point `attach_quickstart` at configuration stored in environment variables. The
helper first checks `MERE_QUICKSTART_AUTH_FILE` (pointing to a JSON file) and then `MERE_QUICKSTART_AUTH`
(inline JSON). The `.env.example` file documents both options so teams can either mount secrets from their
manager into files or export them inline. The loader resolves `_FILE` first so you can keep real credentials
outside the repository.

Example using inline configuration:

```python
from mere import AppConfig, MereApp
from mere.quickstart import (
    DEFAULT_QUICKSTART_AUTH,
    QuickstartAuthConfig,
    QuickstartPasskey,
    QuickstartTenant,
    QuickstartUser,
    attach_quickstart,
)

app = MereApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme",)))

auth_config = QuickstartAuthConfig(
    tenants=(
        QuickstartTenant(
            slug="acme",
            name="Acme Rockets",
            users=(
                QuickstartUser(
                    id="usr_acme_owner",
                    email="founder@acme.test",
                    password="founder-pass",
                    passkeys=(QuickstartPasskey(credential_id="key-1", secret="founder-secret"),),
                    mfa_code="654321",
                ),
            ),
        ),
    ),
    admin=DEFAULT_QUICKSTART_AUTH.admin,
)

attach_quickstart(app, auth_config=auth_config)
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
