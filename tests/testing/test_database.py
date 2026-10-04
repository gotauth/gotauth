"""fresh_database_url creates an isolated Postgres database and removes it."""

from __future__ import annotations

import os

import pytest

from gotauth.testing import fresh_database_url


@pytest.mark.postgres
async def test_fresh_database_is_created_and_dropped() -> None:
    asyncpg = pytest.importorskip("asyncpg")
    base = os.environ["GOTAUTH_TEST_POSTGRES_URL"]
    created: list[str] = []
    async for url in fresh_database_url(base):
        name = url.rsplit("/", 1)[1]
        created.append(name)
        connection = await asyncpg.connect(url)
        try:
            assert await connection.fetchval("SELECT current_database()") == name
        finally:
            await connection.close()
    admin = await asyncpg.connect(base)
    try:
        left = await admin.fetchval(
            "SELECT count(*) FROM pg_database WHERE datname = $1", created[0]
        )
    finally:
        await admin.close()
    assert left == 0
