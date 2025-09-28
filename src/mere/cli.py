"""Command line utilities for Mere."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .database import Database
from .metadata import PROJECT_NAME
from .migrations import Migration, MigrationRunner, MigrationScope, generate_schema_migrations
from .orm import Model
from .tenancy import TenantContext


@dataclass(slots=True)
class CLIEnvironment:
    """All dependencies required to execute CLI operations."""

    database: Database
    tenants: list[TenantContext]
    migrations: list[Migration]


QUALITY_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("ruff", "check"),
    ("ty", "check", "src"),
    ("pytest",),
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def quality() -> int:
    """Run the project quality checks in sequence."""

    for command in QUALITY_COMMANDS:
        print(f"$ {' '.join(command)}", flush=True)
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            return result.returncode
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROJECT_NAME, description="Mere management commands")
    sub = parser.add_subparsers(dest="command", required=True)

    migrate = sub.add_parser("migrate", help="Run database migrations")
    migrate.add_argument("--module", default="migrations", help="Module providing database and migrations")
    migrate.add_argument("--scope", choices=["all", "admin", "tenant"], default="all")
    migrate.add_argument("--tenant", action="append", default=[], help="Restrict tenant-scoped migrations")
    migrate.add_argument("--only-background", action="store_true", help="Run only migrations marked as background")
    migrate.add_argument("--skip-background", action="store_true", help="Skip background migrations")
    migrate.set_defaults(func=_cmd_migrate)

    make = sub.add_parser("make-migration", help="Generate a migration skeleton")
    make.add_argument("name", help="Human readable migration name")
    make.add_argument("--directory", default="migrations", help="Directory for the new migration file")
    make.add_argument(
        "--import",
        dest="imports",
        action="append",
        default=[],
        help="Additional modules to import so model declarations are discovered",
    )
    make.set_defaults(func=_cmd_make_migration)

    snapshot = sub.add_parser("snapshot-test-data", help="Write a canonical SQL snapshot of test data")
    snapshot.add_argument("--module", default="migrations", help="Module providing database and migrations")
    snapshot.add_argument("--output", default="tests/test_data.sql", help="Destination file for the SQL snapshot")
    snapshot.add_argument("--skip-admin", action="store_true", help="Skip admin scope data in the snapshot")
    snapshot.set_defaults(func=_cmd_snapshot)

    return parser


def _cmd_migrate(args: argparse.Namespace) -> int:
    if args.only_background and args.skip_background:
        raise SystemExit("Cannot use --only-background with --skip-background")
    env = _load_environment(args.module)
    runner = MigrationRunner(env.database, migrations=env.migrations, tenant_provider=lambda: env.tenants)

    scope = None
    if args.scope == "admin":
        scope = MigrationScope.ADMIN
    elif args.scope == "tenant":
        scope = MigrationScope.TENANT

    tenants = None
    if args.tenant:
        mapping = {tenant.tenant: tenant for tenant in env.tenants}
        selected: list[TenantContext] = []
        for tenant_name in args.tenant:
            try:
                selected.append(mapping[tenant_name])
            except KeyError as exc:  # pragma: no cover - defensive
                raise SystemExit(f"Unknown tenant '{tenant_name}'") from exc
        tenants = selected

    background = None
    if args.only_background:
        background = True
    elif args.skip_background:
        background = False

    applied = asyncio.run(runner.run_all(scope=scope, tenants=tenants, background=background))
    if not applied:
        print("No migrations executed")
    else:
        for label in applied:
            print(f"applied {label}")
    return 0


def _cmd_make_migration(args: argparse.Namespace) -> int:
    for module_name in args.imports:
        importlib.import_module(module_name)

    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    slug = _slugify(args.name)
    path = directory / f"{slug}.py"
    if path.exists():
        raise SystemExit(f"Migration file {path} already exists")

    admin_models, tenant_models = _models_by_scope()
    content = _render_migration_template(slug, admin_models, tenant_models)
    path.write_text(content, encoding="utf-8")
    print(f"created {path}")
    return 0


def _cmd_snapshot(args: argparse.Namespace) -> int:
    env = _load_environment(args.module)
    runner = MigrationRunner(env.database, migrations=env.migrations, tenant_provider=lambda: env.tenants)
    tenants = env.tenants
    if args.skip_admin:
        include_admin = False
    else:
        include_admin = True
    asyncio.run(runner.snapshot_test_data(Path(args.output), tenants=tenants, include_admin=include_admin))
    print(f"wrote {args.output}")
    return 0


def _load_environment(module_name: str) -> CLIEnvironment:
    module = importlib.import_module(module_name)
    database = None
    database_factory = getattr(module, "get_database", None)
    if callable(database_factory):
        database = database_factory()
    elif hasattr(module, "DATABASE"):
        database = getattr(module, "DATABASE")
    if database is None:
        raise SystemExit(f"Module {module_name!r} must define get_database() or DATABASE")
    if not isinstance(database, Database):  # pragma: no cover - defensive
        raise SystemExit(f"Module {module_name!r} did not return a Database instance")

    tenants_raw = ()
    tenant_factory = getattr(module, "get_tenants", None)
    if callable(tenant_factory):
        tenants_raw = tenant_factory()
    elif hasattr(module, "TENANTS"):
        tenants_raw = getattr(module, "TENANTS")
    tenants = list(tenants_raw)

    migrations: list[Migration] = []
    include_models = getattr(module, "INCLUDE_MODEL_MIGRATIONS", True)
    if include_models:
        importlib.import_module("mere.models")
        migrations.extend(generate_schema_migrations(name_prefix="auto"))
    migration_factory = getattr(module, "get_migrations", None)
    if callable(migration_factory):
        migrations.extend(migration_factory())
    elif hasattr(module, "MIGRATIONS"):
        migrations.extend(getattr(module, "MIGRATIONS"))

    return CLIEnvironment(database=database, tenants=tenants, migrations=migrations)


def _models_by_scope() -> tuple[list[type[Model]], list[type[Model]]]:
    importlib.import_module("mere.models")
    admin: list[type[Model]] = []
    tenant: list[type[Model]] = []
    for model in Model.declared_models():
        info = getattr(model, "__model_info__", None)
        if info is None:
            continue
        if info.scope == "admin":
            admin.append(model)
        elif info.scope == "tenant":
            tenant.append(model)
    admin.sort(key=lambda model: getattr(model, "__model_info__").table)
    tenant.sort(key=lambda model: getattr(model, "__model_info__").table)
    return admin, tenant


def _render_migration_template(
    slug: str,
    admin_models: Sequence[type[Model]],
    tenant_models: Sequence[type[Model]],
) -> str:
    lines: list[str] = [
        "from __future__ import annotations",
        "",
        '"""Auto-generated migration skeleton."""',
        "",
        "from mere.migrations import Migration, MigrationScope, create_table_for_model",
    ]

    imports: dict[str, list[str]] = {}
    for model in list(admin_models) + list(tenant_models):
        imports.setdefault(model.__module__, []).append(model.__name__)

    if imports:
        lines.append("")
        for module_name in sorted(imports):
            names = ", ".join(sorted(set(imports[module_name])))
            lines.append(f"from {module_name} import {names}")

    lines.append("")
    lines.append("MIGRATIONS = [")

    if admin_models:
        lines.append("    Migration(")
        lines.append(f'        name="{slug}_admin",')
        lines.append("        scope=MigrationScope.ADMIN,")
        lines.append("        operations=(")
        for model in admin_models:
            lines.append(f"            create_table_for_model({model.__name__}),")
        lines.append("        ),")
        lines.append("    ),")

    if tenant_models:
        lines.append("    Migration(")
        lines.append(f'        name="{slug}_tenant",')
        lines.append("        scope=MigrationScope.TENANT,")
        lines.append("        operations=(")
        for model in tenant_models:
            lines.append(f"            create_table_for_model({model.__name__}),")
        lines.append("        ),")
        lines.append('        # target_tenants=("customer",),')
        lines.append("    ),")

    if not admin_models and not tenant_models:
        lines.append("    # Add Migration(...) entries here.")

    lines.append("]")
    lines.append("")
    return "\n".join(lines)


def _slugify(name: str) -> str:
    tokens = ["".join(ch for ch in part if ch.isalnum()) for part in name.lower().split()]
    slug = "_".join(token for token in tokens if token)
    return slug or "migration"


__all__ = ["main"]
