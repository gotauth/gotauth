"""The ``gotauth`` subcommands. SQLAlchemy and Alembic are imported only when used."""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
import uuid
from argparse import Namespace
from pathlib import Path
from typing import Any

__all__ = [
    "cmd_generate",
    "cmd_init",
    "cmd_migrate",
    "cmd_secret",
    "delegate",
    "load_auth",
]

_HINT = 'This needs the SQLAlchemy extra: pip install "gotauth[sqlalchemy,postgres]"'


class CliError(Exception):
    """A user-facing error: printed without a traceback, exit code 1."""


def _err(message: str) -> None:
    sys.stderr.write(message.rstrip() + "\n")


def load_env(path: Path) -> None:
    """Set variables from a ``.env`` file that the environment does not set yet."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def load_auth(spec: str) -> Any:  # Any: the user's GotAuth instance
    """Import ``module:attr`` from the current directory.

    Raises:
        CliError: When the module or attribute is missing, or an extra is not installed.
    """
    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        msg = f"--auth must look like module:attr, got {spec!r}"
        raise CliError(msg)
    cwd = str(Path.cwd())
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    load_env(Path(cwd) / ".env")  # what `gotauth init` wrote
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name in {"sqlalchemy", "alembic", "asyncpg", "aiosqlite"}:
            raise CliError(_HINT) from exc
        msg = f"cannot import {module_name!r} from {cwd}: {exc}"
        raise CliError(msg) from exc
    except KeyError as exc:
        msg = f"importing {module_name!r} failed: environment variable {exc} is not set"
        raise CliError(msg) from exc
    except Exception as exc:
        msg = f"importing {module_name!r} failed: {type(exc).__name__}: {exc}"
        raise CliError(msg) from exc
    auth = getattr(module, attr, None)
    if auth is None:
        msg = f"{module_name!r} has no attribute {attr!r}"
        raise CliError(msg)
    return auth


def _sqlalchemy_adapter(auth: Any) -> Any:  # Any: SqlAlchemyAdapter, imported lazily
    try:
        from gotauth.storage.sqlalchemy import SqlAlchemyAdapter
    except ModuleNotFoundError as exc:
        raise CliError(_HINT) from exc
    database = auth.database
    if not isinstance(database, SqlAlchemyAdapter):
        msg = "this command needs GotAuth(database=sqlalchemy_adapter(engine))"
        raise CliError(msg)
    return database


# ---------------------------------------------------------------- secret


def cmd_secret(_: Namespace) -> int:
    """Print a new 43-character secret."""
    from gotauth.crypto import random_token

    sys.stdout.write(random_token() + "\n")
    return 0


# ---------------------------------------------------------------- init

_AUTH_TEMPLATE = '''"""GotAuth setup, created by `gotauth init`."""

import os

from sqlalchemy.ext.asyncio import create_async_engine

from gotauth import GotAuth
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

engine = create_async_engine(os.environ.get("DATABASE_URL", {database_url!r}))

auth = GotAuth(
    database=sqlalchemy_adapter(engine),
    secret=os.environ["GOTAUTH_SECRET"],
    base_url=os.environ.get("GOTAUTH_BASE_URL", "http://localhost:8000"),
)
'''

_SNIPPET = """
Next steps:
  1. Load .env into the environment (for example with python-dotenv).
  2. Create the tables:   gotauth migrate
  3. Add GotAuth to your FastAPI app:

       from auth import auth

       app.include_router(auth.fastapi.router(), prefix="{base_path}")
       app.mount("/", auth.well_known())  # last, so it does not shadow your routes
"""


def _write_secret(env_file: Path) -> bool:
    """Add GOTAUTH_SECRET to ``env_file`` unless it already has one."""
    from gotauth.crypto import random_token

    existing = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
    for line in existing.splitlines():
        if line.strip().startswith("GOTAUTH_SECRET="):
            return False
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    with env_file.open("a", encoding="utf-8") as handle:
        handle.write(f"{prefix}GOTAUTH_SECRET={random_token()}\n")
    if os.name == "posix":
        env_file.chmod(0o600)
    return True


def cmd_init(args: Namespace) -> int:
    """Write auth.py and a secret in .env; never overwrite without --force."""
    directory = Path(args.dir)
    directory.mkdir(parents=True, exist_ok=True)
    auth_file = directory / "auth.py"
    if auth_file.exists() and not args.force:
        _err(f"{auth_file} exists; leaving it alone (use --force to replace it)")
    else:
        auth_file.write_text(
            _AUTH_TEMPLATE.format(database_url=args.database_url), encoding="utf-8"
        )
        sys.stdout.write(f"wrote {auth_file}\n")
    env_file = directory / ".env"
    if _write_secret(env_file):
        sys.stdout.write(f"added GOTAUTH_SECRET to {env_file}\n")
    else:
        sys.stdout.write(f"{env_file} already has GOTAUTH_SECRET; kept it\n")
    sys.stdout.write(_SNIPPET.format(base_path="/api/auth"))
    return 0


# ---------------------------------------------------------------- migrate


def cmd_migrate(args: Namespace) -> int:
    """Create missing tables and columns; print what needs a person."""
    auth = load_auth(args.auth)
    database = _sqlalchemy_adapter(auth)
    from gotauth.storage.sqlalchemy import create_missing

    async def run() -> Any:  # Any: MigrationPlan
        try:
            return await create_missing(
                database.engine,
                auth.schema,
                table_prefix=auth.config.advanced.table_prefix,
                dry_run=args.dry_run,
            )
        finally:
            await database.engine.dispose()

    plan = asyncio.run(run())
    if plan.empty:
        sys.stdout.write("The database is up to date.\n")
        return 0
    verb = "Would run" if args.dry_run else "Ran"
    if plan.statements:
        sys.stdout.write(f"-- {verb}:\n" + "\n".join(plan.statements) + "\n")
    if plan.manual:
        sys.stdout.write(
            "-- Not run (required columns without a default); review, then run:\n"
            + "\n".join(plan.manual)
            + "\n"
        )
    return 0


# ---------------------------------------------------------------- generate


def cmd_generate(args: Namespace) -> int:
    """Print DDL (--sql) or write an Alembic revision for auth.schema."""
    auth = load_auth(args.auth)
    prefix = auth.config.advanced.table_prefix
    if args.sql:
        try:
            from gotauth.storage.sqlalchemy import schema_ddl
        except ModuleNotFoundError as exc:
            raise CliError(_HINT) from exc
        sys.stdout.write(
            schema_ddl(auth.schema, dialect=args.dialect, table_prefix=prefix)
        )
        return 0
    database = _sqlalchemy_adapter(auth)
    from gotauth.cli._alembic import write_revision

    config = Path(args.config)
    if not config.exists():
        msg = (
            f"{config} not found. Create an Alembic project first "
            "(alembic init -t async migrations), or use --sql."
        )
        raise CliError(msg)
    path = asyncio.run(
        write_revision(
            database.engine,
            auth.schema,
            table_prefix=prefix,
            config_file=config,
            message=args.message,
            rev_id=uuid.uuid4().hex[:12],
        )
    )
    if path is None:
        sys.stdout.write("No changes: the database matches auth.schema.\n")
    else:
        sys.stdout.write(f"wrote {path}\n")
    return 0


# ---------------------------------------------------------------- delegated


def delegate(command: str, argv: list[str]) -> int:
    """Run ``check`` (G3) or ``import`` (I1) when that work package is present."""
    targets = {
        "check": "gotauth.checkup",
        "import": "gotauth.importers.fastapi_users",
    }
    try:
        module = importlib.import_module(targets[command])
        entry = module.main
    except (ModuleNotFoundError, AttributeError):
        _err(f"gotauth {command} is not available in this version")
        return 2
    return int(entry(argv))
