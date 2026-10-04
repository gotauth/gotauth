"""Smoke tests for the package layout, the lazy exports and the dev services."""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import subprocess
import sys
from types import ModuleType

import pytest

import gotauth

SKELETON_MODULES = [
    "gotauth.checkup",
    "gotauth.cli",
    "gotauth.contracts",
    "gotauth.core",
    "gotauth.crypto",
    "gotauth.email",
    "gotauth.email_password",
    "gotauth.importers",
    "gotauth.importers.fastapi_users",
    "gotauth.integrations",
    "gotauth.integrations.asgi",
    "gotauth.integrations.fastapi",
    "gotauth.integrations.mcp",
    "gotauth.interop",
    "gotauth.plugins",
    "gotauth.plugins.admin",
    "gotauth.plugins.agent",
    "gotauth.plugins.api_key",
    "gotauth.plugins.magic_link",
    "gotauth.plugins.oauth_provider",
    "gotauth.plugins.organization",
    "gotauth.plugins.passkey",
    "gotauth.plugins.two_factor",
    "gotauth.sessions",
    "gotauth.social",
    "gotauth.storage",
    "gotauth.storage.memory",
    "gotauth.storage.sqlalchemy",
    "gotauth.testing",
]

# Modules that must import with only the core dependencies (CONTRACTS section 0,
# AGENT-RULES 5): framework and extra packages load lazily or only in integrations.
CORE_MODULES = [
    "gotauth",
    "gotauth.checkup",
    "gotauth.cli",
    "gotauth.contracts",
    "gotauth.core",
    "gotauth.crypto",
    "gotauth.email",
    "gotauth.email_password",
    "gotauth.importers",
    "gotauth.integrations",
    "gotauth.interop",
    "gotauth.plugins",
    "gotauth.sessions",
    "gotauth.social",
    "gotauth.storage",
    "gotauth.storage.memory",
    "gotauth.testing",
]

# Top-level modules installed by the optional extras in pyproject.toml.
EXTRA_MODULES = [
    "aiosmtplib",
    "aiosqlite",
    "alembic",
    "argon2",
    "asyncpg",
    "bcrypt",
    "fastapi",
    "fastmcp",
    "litestar",
    "mcp",
    "redis",
    "sqlalchemy",
    "starlette",
    "webauthn",
]

LAZY_EXPORTS = ["AuthError", "GotAuth", "Principal", "Session", "User"]


@pytest.mark.parametrize("name", SKELETON_MODULES)
def test_module_imports(name: str) -> None:
    assert isinstance(importlib.import_module(name), ModuleType)


def test_version_matches_distribution() -> None:
    assert gotauth.__version__ == importlib.metadata.version("gotauth")


def test_lazy_exports_are_public() -> None:
    for name in LAZY_EXPORTS:
        assert name in gotauth.__all__
        assert name in dir(gotauth)


def test_unknown_attribute_raises_attribute_error() -> None:
    with pytest.raises(AttributeError, match="no_such_name"):
        _ = gotauth.no_such_name


def test_console_script_points_to_cli() -> None:
    scripts = importlib.metadata.entry_points(group="console_scripts", name="gotauth")
    assert [entry.value for entry in scripts] == ["gotauth.cli:main"]
    assert callable(importlib.import_module("gotauth.cli").main)


def test_core_modules_load_no_extras() -> None:
    # A fresh interpreter, because other tests may already have imported the extras.
    code = (
        "import importlib, sys\n"
        f"for name in {CORE_MODULES!r}:\n"
        "    importlib.import_module(name)\n"
        f"loaded = [name for name in {EXTRA_MODULES!r} if name in sys.modules]\n"
        "sys.stdout.write(','.join(loaded))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout == "", f"core modules imported extras: {result.stdout}"


@pytest.mark.postgres
async def test_postgres_service_is_reachable() -> None:
    asyncpg = pytest.importorskip("asyncpg")
    connection = await asyncpg.connect(os.environ["GOTAUTH_TEST_POSTGRES_URL"])
    try:
        assert await connection.fetchval("SELECT 1") == 1
    finally:
        await connection.close()


@pytest.mark.redis
async def test_redis_service_is_reachable() -> None:
    redis_asyncio = pytest.importorskip("redis.asyncio")
    client = redis_asyncio.from_url(os.environ["GOTAUTH_TEST_REDIS_URL"])
    try:
        assert await client.ping() is True
    finally:
        await client.aclose()
