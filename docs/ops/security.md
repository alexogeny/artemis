# Secret hygiene

Mere ships with fixture data for the developer bootstrap (sample tenants, passkeys, and passwords). Those
values are intentionally synthetic—they are not live credentials—and exist only to demonstrate the framework's
multi-tenant flows. To keep production environments safe:

- Provide real bootstrap identities through `MERE_BOOTSTRAP_AUTH` or `MERE_BOOTSTRAP_AUTH_FILE`. Both knobs
  are documented in `.env.example` so developers can mount secrets from their secret manager or export inline
  JSON for temporary sandboxes.
- Keep bootstrap payloads and other credentials outside of source control. Use `.env` files that are ignored by
  Git or secret managers that project the values at runtime.
- Rotate any temporary credentials used during demos or QA and avoid reusing them across environments.
- Audit new code for accidentally committed secrets. (A repository-wide search confirms that only the fixture
  values mentioned above are present.)

Follow these practices before merging features or publishing the documentation site.
