"""The gotauth CLI, called through main([...]) in a temporary project."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from gotauth.cli import main
from gotauth.testing import fresh_database_url

AUTH_FILE = """
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from gotauth import GotAuth
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

engine = create_async_engine({url!r}, poolclass=NullPool)
auth = GotAuth(
    database=sqlalchemy_adapter(engine),
    secret="s" * 64,
    base_url="http://localhost:8000",
    email_password={{"enabled": False}},
)
"""


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.chdir(tmp_path)
    # Alembic's env.py calls logging.config.fileConfig, which disables every existing
    # logger; restore them so later tests still see GotAuth's log records.
    loggers = logging.root.manager.loggerDict
    disabled = {
        name: logger.disabled
        for name, logger in loggers.items()
        if isinstance(logger, logging.Logger)
    }
    root_level = logging.root.level
    yield tmp_path
    if str(tmp_path) in sys.path:
        sys.path.remove(str(tmp_path))
    for name, logger in list(loggers.items()):
        if isinstance(logger, logging.Logger):
            logger.disabled = disabled.get(name, False)
    logging.root.setLevel(root_level)


def write_auth(project: Path, url: str) -> str:
    """Write a uniquely named auth module and return its --auth spec."""
    name = f"auth_{uuid.uuid4().hex[:8]}"
    (project / f"{name}.py").write_text(AUTH_FILE.format(url=url), encoding="utf-8")
    return f"{name}:auth"


def table_names(url: str) -> set[str]:
    async def run() -> set[str]:
        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                return await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
        finally:
            await engine.dispose()

    return asyncio.run(run())


# ---------------------------------------------------------------- init and secret


def test_secret(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["secret"]) == 0
    assert len(capsys.readouterr().out.strip()) == 43


def test_init_writes_files_and_never_overwrites(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["init"]) == 0
    auth_py = (project / "auth.py").read_text(encoding="utf-8")
    assert "sqlalchemy_adapter" in auth_py
    env = (project / ".env").read_text(encoding="utf-8")
    secret = env.strip().split("=", 1)[1]
    assert len(secret) >= 32
    if os.name == "posix":
        assert (project / ".env").stat().st_mode & 0o777 == 0o600
    assert 'app.mount("/", auth.well_known())' in capsys.readouterr().out
    (project / "auth.py").write_text("# mine\n", encoding="utf-8")
    assert main(["init"]) == 0
    assert (project / "auth.py").read_text(encoding="utf-8") == "# mine\n"
    assert (project / ".env").read_text(encoding="utf-8") == env
    assert main(["init", "--force"]) == 0
    assert "sqlalchemy_adapter" in (project / "auth.py").read_text(encoding="utf-8")


def test_init_keeps_an_existing_env(project: Path) -> None:
    (project / ".env").write_text("OTHER=1", encoding="utf-8")
    assert main(["init"]) == 0
    lines = (project / ".env").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "OTHER=1"
    assert lines[1].startswith("GOTAUTH_SECRET=")


# ---------------------------------------------------------------- delegated


def test_check_without_g3_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "gotauth.checkup", None)
    assert main(["check", "."]) == 2
    assert "not available in this version" in capsys.readouterr().err


def test_check_delegates_to_g3(project: Path) -> None:
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert main(["check", str(project)]) == 0


def test_import_runs_the_fastapi_users_importer(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["import", "fastapi-users", "--help"]) == 0
    assert "--source-url" in capsys.readouterr().out


# ---------------------------------------------------------------- errors


def test_missing_auth_module(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["migrate", "--auth", "nope:auth"]) == 1
    assert "cannot import 'nope'" in capsys.readouterr().err


def test_bad_auth_spec(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["migrate", "--auth", "nocolon"]) == 1
    assert "module:attr" in capsys.readouterr().err


# ---------------------------------------------------------------- migrate and generate


def test_migrate_sqlite(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url = f"sqlite+aiosqlite:///{project / 'app.db'}"
    spec = write_auth(project, url)
    assert main(["migrate", "--auth", spec, "--dry-run"]) == 0
    assert "Would run" in capsys.readouterr().out
    assert table_names(url) == set()
    assert main(["migrate", "--auth", spec]) == 0
    assert {
        "auth_user",
        "auth_session",
        "auth_account",
        "auth_verification",
    } <= table_names(url)
    assert main(["migrate", "--auth", spec]) == 0
    assert "up to date" in capsys.readouterr().out


def test_generate_sql(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spec = write_auth(project, f"sqlite+aiosqlite:///{project / 'x.db'}")
    assert main(["generate", "--auth", spec, "--sql", "--dialect", "sqlite"]) == 0
    assert "CREATE TABLE auth_user" in capsys.readouterr().out


def test_generate_needs_an_alembic_project(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    spec = write_auth(project, f"sqlite+aiosqlite:///{project / 'x.db'}")
    assert main(["generate", "--auth", spec]) == 1
    assert "alembic init" in capsys.readouterr().err


def alembic_cycle(project: Path, url: str) -> None:
    config_file = project / "alembic.ini"
    command.init(
        Config(str(config_file)), str(project / "migrations"), template="async"
    )
    ini = config_file.read_text(encoding="utf-8")
    ini = ini.replace(
        "sqlalchemy.url = driver://user:pass@localhost/dbname",
        f"sqlalchemy.url = {url}",
    )
    config_file.write_text(ini, encoding="utf-8")
    spec = write_auth(project, url)
    # Another app table must never show up in GotAuth's migrations.
    asyncio.run(_create_unrelated(url))
    assert main(["generate", "--auth", spec, "-m", "gotauth"]) == 0
    versions = list((project / "migrations" / "versions").glob("*.py"))
    assert len(versions) == 1
    source = versions[0].read_text(encoding="utf-8")
    assert "app_orders" not in source
    config = Config(str(config_file))
    command.upgrade(config, "head")
    assert {"auth_user", "auth_session", "app_orders"} <= table_names(url)
    assert main(["generate", "--auth", spec]) == 0  # nothing left to do
    assert len(list((project / "migrations" / "versions").glob("*.py"))) == 1
    command.downgrade(config, "base")
    remaining = table_names(url)
    assert "auth_user" not in remaining and "app_orders" in remaining
    command.upgrade(config, "head")
    assert "auth_user" in table_names(url)


async def _create_unrelated(url: str) -> None:
    from sqlalchemy import text

    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE app_orders (id INTEGER PRIMARY KEY)"))
    finally:
        await engine.dispose()


def test_alembic_sqlite(project: Path) -> None:
    alembic_cycle(project, f"sqlite+aiosqlite:///{project / 'app.db'}")


@pytest.mark.postgres
def test_alembic_postgres(project: Path) -> None:
    base = os.environ["GOTAUTH_TEST_POSTGRES_URL"].replace(
        "postgresql://", "postgresql+asyncpg://", 1
    )

    # Alembic's async env.py runs its own event loop, so the cycle runs in a thread
    # while this loop keeps the fresh database alive.
    async def run() -> None:
        async for url in fresh_database_url(base):
            await asyncio.to_thread(alembic_cycle, project, url)

    asyncio.run(run())


def test_init_then_migrate_reads_the_env_file(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOTAUTH_SECRET", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{project / 'init.db'}")
    assert main(["init"]) == 0
    module = f"auth_{uuid.uuid4().hex[:8]}"
    (project / "auth.py").rename(project / f"{module}.py")
    assert main(["migrate", "--auth", f"{module}:auth"]) == 0
    assert "auth_user" in table_names(os.environ["DATABASE_URL"])


def test_auth_import_errors_are_clean(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MISSING_VAR", raising=False)
    (project / "broken_auth.py").write_text(
        "import os\nauth = os.environ['MISSING_VAR']\n", encoding="utf-8"
    )
    assert main(["migrate", "--auth", "broken_auth:auth"]) == 1
    assert "MISSING_VAR" in capsys.readouterr().err
