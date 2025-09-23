# artemis

backend

## Audit log sanitization

Audit entries are sanitized using model metadata before they are persisted. When
`AuditTrail.record_model_change` runs, it removes any fields listed in a
model's `redacted_fields` from the recorded `changes` as well as from the
`metadata["before"]` snapshot prior to serialization. Models marked with
`exposed=False` default to redacting every column unless they enumerate the
subset of non-sensitive attributes in `redacted_fields`. When introducing new
models, make sure secrets, tokens, and other credentials are included in
`redacted_fields` so the audit log retains useful context without leaking
protected values.

## SAML provider configuration

Artemis validates SAML assertions by honoring both the `<Conditions>` and `<SubjectConfirmationData>`
timestamps inside each assertion. Providers can tune that behavior on `TenantSamlProvider`:

* `clock_skew_seconds` (default: 120) expands the acceptance window on both sides when comparing the
  `NotBefore` and `NotOnOrAfter` attributes. Increase this value when your identity provider's clock runs
  slightly ahead or behind your cluster to avoid spurious `assertion_not_yet_valid` or `assertion_expired`
  errors.
* `allowed_audiences` enumerates the `<Audience>` values that Artemis will accept. When populated, at least
  one audience in the assertion must match the configured list, otherwise validation fails with
  `invalid_audience`. Leave the list empty to accept any audience from the identity provider.

All comparison happens in UTC; assertions that use a trailing `Z` or explicit `+00:00` offsets are accepted.

