# Observability

Mere ships with structured observability hooks that expose request traces, metrics, and audit records.

## Configuring observability

Provide `ObservabilityConfig` when constructing the app:

```python
from mere import AppConfig, MereApp
from mere.observability import Observability, ObservabilityConfig

observability = Observability(config=ObservabilityConfig(service_name="mere-demo"))
app = MereApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme",)))
app = MereApp(
    AppConfig(
        site="demo",
        domain="local.test",
        allowed_tenants=("acme",),
        observability=observability,
    )
)
```

The observability hooks expose async context managers for span creation, structured logging, and
emitting metrics. The default implementation writes JSON events to stdout, but you can inject custom
providers to integrate with OpenTelemetry, Honeycomb, or any other tracing system.

### Opting in to external sinks

OpenTelemetry, Sentry, and Datadog integrations are disabled by default. Enable only the sinks you
need to avoid leaking tenant identifiers accidentally:

```python
from mere.observability import ObservabilityConfig

config = ObservabilityConfig(
    opentelemetry_enabled=True,
    sentry_enabled=True,
    datadog_enabled=True,
)
```

These switches honour the `MERE_OBSERVABILITY_OPENTELEMETRY_ENABLED`,
`MERE_OBSERVABILITY_SENTRY_ENABLED`, and `MERE_OBSERVABILITY_DATADOG_ENABLED` environment variables,
so you can flip them per deployment without touching code.

### Controlling sensitive fields

By default Mere redacts request paths, exception messages, and tenant identifiers from structured
logs and telemetry metadata. Override the behaviour by configuring `LoggingRedactionConfig` and
`TenantRedactionConfig` on the observability settings:

```python
from mere.observability import (
    LoggingRedactionConfig,
    ObservabilityConfig,
    TenantRedactionConfig,
)

config = ObservabilityConfig(
    logging=LoggingRedactionConfig(
        request_path="hash",  # "redact", "hash", or "raw"
        exception_message="raw",
        hash_salt="deploy-secret",  # optional salt to stabilise hashes
    ),
    tenant=TenantRedactionConfig(
        log_fields="hash",
        sentry_tags="redact",
        datadog_tags="hash",
    ),
)
```

`hash` mode keeps correlation while avoiding raw values, and `raw` opt-in restores the previous
behaviour for trusted sinks. Tenant masking applies to request logs, Sentry tags (including
breadcrumbs), and Datadog tags.

## Audit trails

Audit trails capture sensitive operations in admin and tenant scopes. Use `AuditTrail` to wrap critical
workflows:

```python
from mere.audit import AuditTrail

async with AuditTrail.current().record(action="tenant.reset-password", tenant=tenant.tenant):
    ...
```

The audit subsystem includes helpers for forwarding events to chatops integrations and long-term
storage systems.
