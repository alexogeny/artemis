# HTTP utilities

Mere exposes a comprehensive HTTP toolkit that mirrors the ASGI specification while adding
high-level helpers for responses and WebSockets.

## Status helpers

`mere.http` includes predicates such as `is_success`, `is_client_error`, and `ensure_status` which
make it simple to enforce consistent status handling in handlers and middleware.

## Response types

Use `JSONResponse` and `PlainTextResponse` for structured output. Both apply `DEFAULT_SECURITY_HEADERS`
so responses include strict transport security, frame protection, and content type metadata by default.

## WebSockets

`mere.websockets.WebSocket` wraps the ASGI scope with typed send/receive helpers and integrates with the
same dependency injection system used for HTTP handlers. The `_status_to_websocket_close` helper maps
HTTP statuses to the appropriate WebSocket close codes, ensuring graceful shutdown of tenant
connections.
