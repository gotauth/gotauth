"""``fresh_database_url``: one throwaway Postgres database per test session."""

from __future__ import annotations

import importlib
import os
import secrets
from collections.abc import AsyncIterator
from typing import Any, Protocol, cast
from urllib.parse import urlsplit, urlunsplit

__all__ = ["fresh_database_url"]


class _Connection(Protocol):
    async def execute(self, query: str) -> str: ...

    async def close(self) -> None: ...


def _connector() -> Any:  # Any: asyncpg.connect; asyncpg is an untyped optional extra
    try:
        asyncpg = importlib.import_module("asyncpg")
    except ImportError as exc:
        msg = 'fresh_database_url() needs asyncpg: pip install "gotauth[postgres]"'
        raise RuntimeError(msg) from exc
    return asyncpg.connect


async def _execute(url: str, statement: str) -> None:
    connection = cast("_Connection", await _connector()(url))
    try:
        await connection.execute(statement)
    finally:
        await connection.close()


async def fresh_database_url(base_url: str) -> AsyncIterator[str]:
    """Create a uniquely named Postgres database and drop it afterwards.

    Use it as a session-scoped async fixture::

        @pytest_asyncio.fixture(scope="session", loop_scope="session")
        async def database_url():
            base = os.environ["GOTAUTH_TEST_POSTGRES_URL"]
            async for url in fresh_database_url(base):
                yield url

    Args:
        base_url: A server URL whose user may create databases, e.g.
            ``postgresql://gotauth:gotauth@postgres:5432/gotauth``. A driver suffix such
            as ``postgresql+asyncpg`` is kept in the yielded URL.

    Yields:
        ``base_url`` pointing at the new database.
    """
    parts = urlsplit(base_url)
    admin_url = urlunsplit(parts._replace(scheme="postgresql"))
    # Random, so parallel workers and worktrees never share a database.
    name = f"gotauth_test_{os.getpid()}_{secrets.token_hex(6)}"
    await _execute(admin_url, f'CREATE DATABASE "{name}"')
    try:
        yield urlunsplit(parts._replace(path="/" + name))
    finally:
        await _execute(admin_url, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
