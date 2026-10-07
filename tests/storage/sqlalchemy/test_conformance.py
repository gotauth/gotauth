"""The adapter conformance suite on SQLite (memory and file) and Postgres."""

from __future__ import annotations

import pytest

from gotauth.contracts import Adapter
from gotauth.testing import adapter_conformance

from .conftest import (
    AutoCreate,
    postgres_engine,
    sqlite_file_engine,
    sqlite_memory_engine,
)


async def make_sqlite_memory() -> Adapter:
    return AutoCreate(sqlite_memory_engine())


async def make_sqlite_file() -> Adapter:
    return AutoCreate(sqlite_file_engine())


async def make_postgres() -> Adapter:
    return AutoCreate(postgres_engine())


class TestSqliteMemory(adapter_conformance(make_sqlite_memory)):
    pass


class TestSqliteFile(adapter_conformance(make_sqlite_file)):
    pass


@pytest.mark.postgres
class TestPostgres(adapter_conformance(make_postgres)):
    pass
