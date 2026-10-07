"""Engines and a self-creating adapter for the SQLAlchemy tests."""

from __future__ import annotations

import asyncio
import os
import tempfile
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool, StaticPool

from gotauth.contracts import Adapter
from gotauth.storage.sqlalchemy import SqlAlchemyAdapter
from gotauth.testing import fresh_database_url

POSTGRES_URL: dict[str, str] = {}


def asyncpg_url(url: str) -> str:
    """Return ``url`` with the asyncpg driver."""
    return url.replace("postgresql://", "postgresql+asyncpg://", 1)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def postgres_url() -> AsyncIterator[str]:
    """A fresh Postgres database for this test session."""
    base = os.environ.get("GOTAUTH_TEST_POSTGRES_URL")
    if not base:
        pytest.skip("GOTAUTH_TEST_POSTGRES_URL is not set")
    async for url in fresh_database_url(asyncpg_url(base)):
        POSTGRES_URL["url"] = url
        yield url


@pytest.fixture(autouse=True)
def _postgres_when_marked(request: pytest.FixtureRequest) -> None:
    """Tests marked ``postgres`` get the session database."""
    if request.node.get_closest_marker("postgres") is not None:
        request.getfixturevalue("postgres_url")


def sqlite_memory_engine() -> AsyncEngine:
    return create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)


def sqlite_file_engine() -> AsyncEngine:
    path = Path(tempfile.mkdtemp()) / "auth.db"
    return create_async_engine(f"sqlite+aiosqlite:///{path}")


def postgres_engine() -> AsyncEngine:
    # NullPool: every test runs on its own event loop, so no connection is reused.
    return create_async_engine(POSTGRES_URL["url"], poolclass=NullPool)


class AutoCreate(SqlAlchemyAdapter):
    """Drops and creates its tables before the first operation (tests only)."""

    def __init__(self, engine: AsyncEngine) -> None:
        super().__init__(engine)
        self._ready = False
        self._ready_lock = asyncio.Lock()

    async def _ensure(self) -> None:
        async with self._ready_lock:
            if self._ready:
                return
            metadata = next(iter(self.tables().values())).metadata
            async with self.engine.begin() as conn:
                await conn.run_sync(metadata.drop_all)
                await conn.run_sync(metadata.create_all)
            self._ready = True

    async def _run(self, *args: Any, **kwargs: Any) -> Any:  # Any: passes through
        await self._ensure()
        return await super()._run(*args, **kwargs)

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[Adapter]:
        await self._ensure()
        async with super().transaction() as tx:
            yield tx
