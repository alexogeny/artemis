# Architecture overview

Mere is organized as a layered system that embraces async-first boundaries and explicit tenant
context propagation.

## Runtime layers

1. **Entry point (`MereApp`)** — wraps the ASGI interfaces for HTTP and WebSocket scopes. Requests flow
   through middleware, dependency injection, and the routing table to reach handlers defined with the
   decorator API.
2. **Tenant resolution** — the `TenantResolver` inspects the host header, matches it against the
   configured tenants, and injects a `TenantContext` into downstream calls. All persistence and
   background tasks receive the context explicitly.
3. **Domain services** — authentication, chatops, audit, observability, and custom services consume the
   runtime metadata and expose typed operations that can be orchestrated per-tenant.
4. **Infrastructure** — the database, ORM, event streams, and serialization layers share reusable
   utilities built on msgspec, rloop, and other Rust-backed primitives.

## Key modules

- `mere.application` implements routing, request dispatch, dependency injection, and background task
  orchestration.
- `mere.config` defines the `AppConfig` struct that declaratively wires tenancy, observability,
  persistence, and external integrations.
- `mere.tenancy` contains the tenant resolution algorithms, including helpers for admin vs tenant scope.
- `mere.database` and `mere.orm` manage tenant-aware database access with schema separation and
  typed models.
- `mere.quickstart` bootstraps authentication, tenancy data, and sample routes so new deployments can be
  exercised immediately.

Each module is designed to run in-thread, in a separate process, or on a remote worker by serializing
messages with msgspec. This keeps the runtime horizontally scalable and safe under concurrent load.
