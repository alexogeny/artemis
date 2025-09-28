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
