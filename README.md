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
