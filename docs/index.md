# Mere

Mere is an asynchronous, multi-tenant web framework that combines Python ergonomics with Rust-backed
performance primitives. It provides a batteries-included platform for building tenant-isolated SaaS
applications with declarative routing, structured observability, and a fully async runtime.

## Key capabilities

- **Tenant-aware runtime** – every request flows through an explicit `TenantContext` so custom logic and
  storage always resolve the correct tenant boundary.
- **Declarative routing** – the `@route`, `@get`, and `@post` decorators expose typed request/response
  surfaces that stay in sync with generated OpenAPI contracts and the TypeScript client.
- **Authentication orchestration** – plug-and-play passkey, password, MFA, and SSO flows managed through the
  bootstrap utilities or your own domain services.
- **Observability hooks** – consistent tracing, metrics, and audit logging surfaces ready for the platform of
  your choice.
- **First-class async** – every subsystem (database, background jobs, WebSockets, streaming events) is built on
  an async execution model so work can scale horizontally across tenants.

The remainder of this documentation explains how to get started, wire the framework into your stack, and
operate a Mere deployment in production.
