# Migrating from FastAPI

FastAPI and Mere both build on top of the ASGI ecosystem. This guide shows how
to bring an existing FastAPI project into Mere incrementally so teams can adopt
tenant-aware routing, observability, and the rest of Mere's batteries without a
full rewrite.

## Install compatibility extras

Install the optional Mere FastAPI extras. They pull in FastAPI as a dependency
for local development and CI:

```shell
uv sync --extra fastapi
```

If you prefer pip:

```shell
pip install "mere[fastapi]"
```

## Mount your FastAPI application

Use :func:`mere.adapters.fastapi.mount_fastapi` to expose a FastAPI application
inside Mere. Requests that match the configured prefix are forwarded to the
legacy FastAPI routes. Startup and shutdown events remain wired so background
tasks and dependency injection behave exactly as before.

```python
from fastapi import FastAPI

from mere import AppConfig, MereApp, mount_fastapi


config = AppConfig(site="demo", domain="example.com", allowed_tenants=("acme", "beta"))
app = MereApp(config)

legacy_api = FastAPI()


@legacy_api.get("/orders/{order_id}")
async def fetch_order(order_id: str) -> dict[str, str]:
    return {"order_id": order_id}


# Expose existing FastAPI routes under /legacy
mount_fastapi(app, legacy_api, prefix="/legacy")


@app.get("/healthz")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}
```

### Routing behaviour

* Requests to `/legacy/...` are forwarded to FastAPI. Other requests are handled
  by Mere routes.
* The FastAPI application's `url_for` continues to generate paths relative to
  its original mounting location thanks to the forwarded ASGI ``root_path``.
* Use different prefixes to stage multiple FastAPI applications.

### Lifespan considerations

`mount_fastapi` automatically ties FastAPI's startup and shutdown events into
Mere's lifecycle. If you call :meth:`mere.application.MereApp.startup` or run
the application through the server helpers, the FastAPI app receives the same
lifespan notifications it expects from Uvicorn or Hypercorn.

If you need to mount another ASGI application without helpers, use
:meth:`mere.application.MereApp.mount_asgi` and provide custom startup/shutdown
callables.

## Cleaning up FastAPI routes

Once routes are migrated to Mere equivalents you can delete them from the
FastAPI application. Because mounting happens at the ASGI layer you can remove
prefixes route-by-route without impacting remaining endpoints.

Consider replacing dependency injections with Mere's dependency provider and
swap JSON models over to `msgspec` structures for maximum performance.
