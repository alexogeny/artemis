# CLI commands

Mere bundles a CLI entry point exposed as `uv run mere`. It provides utilities for migrations,
quality checks, and data snapshots.

## Available commands

| Command | Description |
| ------- | ----------- |
| `mere` | Runs the quality gate sequence (`ruff check`, `ty check`, `pytest`). |
| `mere migrate` | Applies database migrations. Supports `--scope` and `--tenant` selectors. |
| `mere make-migration NAME` | Generates a migration template populated with admin and tenant models. |
| `mere snapshot-test-data` | Writes a canonical SQL snapshot of test fixtures. |

## Custom environments

The CLI loads a `CLIEnvironment` from a module using the `--module` option. Implement
`get_database`, `get_migrations`, and `get_tenants` helpers in that module to provide runtime
components. The module can also expose a `DATABASE` attribute for simple use cases.
