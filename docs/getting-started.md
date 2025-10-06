# Getting started

This guide walks through installing Mere, bootstrapping a tenant-aware application, and running the
quality gates that keep the codebase healthy.

## Installation

Mere ships on PyPI as a standard Python package. The project uses [uv](https://docs.astral.sh/uv/) to
manage dependencies and virtual environments, so the quickest way to get a development environment is:

```shell
uv sync
```

The sync command installs the framework along with development tooling such as `ruff`, `ty`, and
`pytest`. It also pulls in MkDocs and the shadcn theme so documentation can be previewed locally.

## Creating your first app

The framework exposes two entry points: `MereApp` encapsulates the ASGI application while `Mere`
provides a declarative constructor that accepts raw mappings. A minimal tenant-aware service looks
like this:

```python
from mere import AppConfig, MereApp
from mere.routing import get

app = MereApp(AppConfig(site="demo", domain="local.test", allowed_tenants=("acme", "beta")))

@get("/hello")
async def hello() -> dict[str, str]:
    return {"message": "Hello from Mere"}
```

Running the app requires an ASGI server such as `granian`. During development you can launch it with:

```shell
uv run granian --interface rsgi --workers 1 mere.server:create_app
```

The server will resolve requests for `https://acme.demo.local.test` and `https://beta.demo.local.test`
by mapping each hostname to the corresponding tenant context.

### TLS defaults

`ServerConfig` now models TLS assets explicitly. In production profiles (`profile="production"`, the
default) the server refuses to boot unless both `certificate_path` and `private_key_path` point to
PEM-encoded files. Provide a certificate authority bundle through `ca_path` when terminating mutual TLS
(`client_auth_required=True`). Development-oriented profiles (`development`, `dev`, `local`, or `test`)
skip the requirement so you can iterate without generating certificates; when PEM files are present they
are still wired into Granian so HTTPS works end-to-end.

```python
from pathlib import Path

from mere.server import ServerConfig

config = ServerConfig(
    certificate_path=Path("/etc/mere/tls/server.crt"),
    private_key_path=Path("/etc/mere/tls/server.key"),
    ca_path=Path("/etc/mere/tls/clients.pem"),
    profile="production",
    client_auth_required=True,
)
```

## Quality checks

Before committing changes, run the built-in quality command:

```shell
uv run mere
```

The CLI iterates through `ruff check`, `ty check`, and `pytest`, ensuring formatting, type-safety, and
full async test coverage.

## Documentation preview

Docs live in the `docs/` directory and are rendered with MkDocs using the shadcn theme. Start a local
preview server with:

```shell
uv run mkdocs serve
```

MkDocs watches the source files and rebuilds the site automatically as Markdown changes. The site is
ready to be published to GitHub Pages using `uv run mkdocs gh-deploy`, which builds the documentation
and pushes the result to the `gh-pages` branch.
