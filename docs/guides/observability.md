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
