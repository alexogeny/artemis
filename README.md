# artemis

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
