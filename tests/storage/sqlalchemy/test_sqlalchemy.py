"""SQLAlchemy specifics beyond the conformance suite."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from gotauth.contracts import UniqueViolation, Where
from gotauth.contracts.core_schema import CORE_SCHEMA
from gotauth.contracts.schema import Field, ModelSchema, merge_schemas
from gotauth.storage.sqlalchemy import (
    create_missing,
    metadata_for,
    missing_changes,
    schema_ddl,
)
from gotauth.testing._conformance import CONFORMANCE_SCHEMA

from .conftest import (
    AutoCreate,
    postgres_engine,
    sqlite_file_engine,
    sqlite_memory_engine,
)

ENGINES = [
    pytest.param(sqlite_memory_engine, id="sqlite-memory"),
    pytest.param(sqlite_file_engine, id="sqlite-file"),
    pytest.param(
        postgres_engine,
        id="postgres",
        marks=pytest.mark.postgres,
    ),
]

NAME = "\u00e1d\u00e1 \U0001f98a \u540d\u524d"  # accents, an emoji, CJK

PLUGIN_SCHEMA = {
    "widget": ModelSchema(
        name="widget",
        fields={"user_id": Field("string", references=None), "label": Field("string")},
    ),
    "user": ModelSchema(
        name="user", fields={"nickname": Field("string", required=False)}
    ),
}


def core_adapter(make: Callable[[], AsyncEngine], prefix: str = "auth_") -> AutoCreate:
    adapter = AutoCreate(make())
    adapter.bind_schema(CORE_SCHEMA, table_prefix=prefix)
    return adapter


def conf_adapter(make: Callable[[], AsyncEngine]) -> AutoCreate:
    adapter = AutoCreate(make())
    adapter.bind_schema(CONFORMANCE_SCHEMA, table_prefix="conf_")
    return adapter


@pytest.mark.parametrize("make", ENGINES)
async def test_unique_violation_keeps_the_transaction_usable(
    make: Callable[[], AsyncEngine],
) -> None:
    adapter = conf_adapter(make)
    async with adapter.transaction() as tx:
        await tx.create("owner", {"id": "o1", "name": "ada"})
        with pytest.raises(UniqueViolation) as error:
            await tx.create("owner", {"id": "o2", "name": "ada"})
        assert error.value.fields == ("name",)
        await tx.create("owner", {"id": "o3", "name": "bob"})
    assert await adapter.count("owner") == 2


@pytest.mark.parametrize("make", ENGINES)
async def test_unique_together_reports_its_fields(
    make: Callable[[], AsyncEngine],
) -> None:
    adapter = conf_adapter(make)
    await adapter.create("owner", {"id": "o1", "name": "ada"})
    await adapter.create(
        "pet", {"id": "p1", "owner_id": "o1", "kind": "cat", "label": "x"}
    )
    with pytest.raises(UniqueViolation) as error:
        await adapter.create(
            "pet", {"id": "p2", "owner_id": "o1", "kind": "dog", "label": "x"}
        )
    assert set(error.value.fields) == {"owner_id", "label"}


@pytest.mark.parametrize("make", ENGINES)
async def test_round_trips(make: Callable[[], AsyncEngine]) -> None:
    adapter = conf_adapter(make)
    plus_three = datetime(2026, 5, 1, 15, 0, tzinfo=timezone(timedelta(hours=3)))
    await adapter.create(
        "owner",
        {
            "id": "o1",
            "name": NAME,
            "joined_at": plus_three,
            "settings": {"nested": {"list": [1, "two", None]}},
            "tags": ["ünï", "b"],
        },
    )
    row = await adapter.find_one("owner", [Where("name", NAME)])
    assert row is not None
    assert row["joined_at"] == datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    assert row["joined_at"].tzinfo == UTC
    assert row["settings"] == {"nested": {"list": [1, "two", None]}}
    assert row["tags"] == ["ünï", "b"]
    naive = datetime(2026, 1, 1)  # noqa: DTZ001 - the case under test
    with pytest.raises(Exception, match="naive"):
        await adapter.create("owner", {"id": "o2", "name": "x", "joined_at": naive})


@pytest.mark.parametrize("make", ENGINES)
async def test_deleting_a_user_cascades(make: Callable[[], AsyncEngine]) -> None:
    adapter = core_adapter(make)
    now = datetime.now(UTC)
    await adapter.create(
        "user",
        {"id": "u1", "email": "ada@example.com", "created_at": now, "updated_at": now},
    )
    await adapter.create(
        "session",
        {
            "id": "s1",
            "user_id": "u1",
            "token_hash": "h",
            "expires_at": now,
            "created_at": now,
            "updated_at": now,
        },
    )
    await adapter.create(
        "account",
        {
            "id": "a1",
            "user_id": "u1",
            "provider_id": "credential",
            "account_id": "u1",
            "created_at": now,
            "updated_at": now,
        },
    )
    assert await adapter.delete("user", [Where("id", "u1")]) == 1
    assert await adapter.count("session") == 0
    assert await adapter.count("account") == 0


def test_table_names() -> None:
    assert "auth_user" in metadata_for(CORE_SCHEMA).tables
    assert "app_user" in metadata_for(CORE_SCHEMA, table_prefix="app_").tables
    explicit = {"thing": ModelSchema(name="thing", fields={}, table="my_things")}
    assert set(metadata_for(explicit, table_prefix="x_").tables) == {"my_things"}


def test_plugin_tables_and_columns_appear_in_the_ddl() -> None:
    schema = merge_schemas(CORE_SCHEMA, PLUGIN_SCHEMA)
    for dialect in ("postgresql", "sqlite"):
        ddl = schema_ddl(schema, dialect=dialect)
        assert "CREATE TABLE auth_widget" in ddl
        assert "nickname" in ddl
        assert "ON DELETE CASCADE" in ddl


@pytest.mark.parametrize("make", ENGINES)
async def test_sql_output_runs_on_an_empty_database(
    make: Callable[[], AsyncEngine],
) -> None:
    engine = make()
    dialect = engine.dialect.name
    prefix = "ddl_"
    ddl = schema_ddl(CORE_SCHEMA, dialect=dialect, table_prefix=prefix)
    async with engine.begin() as conn:
        await conn.run_sync(
            lambda c: metadata_for(CORE_SCHEMA, table_prefix=prefix).drop_all(c)
        )
        for statement in ddl.split(";"):
            if statement.strip():
                await conn.execute(text(statement))
    plan = await missing_changes(engine, CORE_SCHEMA, table_prefix=prefix)
    assert plan.empty
    await engine.dispose()


@pytest.mark.parametrize("make", ENGINES)
async def test_migrate_is_additive_and_idempotent(
    make: Callable[[], AsyncEngine],
) -> None:
    engine = make()
    prefix = "mig_"
    async with engine.begin() as conn:
        merged = merge_schemas(CORE_SCHEMA, PLUGIN_SCHEMA)
        await conn.run_sync(
            lambda c: metadata_for(merged, table_prefix=prefix).drop_all(c)
        )
        await conn.execute(text("DROP TABLE IF EXISTS mig_unrelated"))
    first = await create_missing(engine, CORE_SCHEMA, table_prefix=prefix)
    assert any("CREATE TABLE mig_user" in s for s in first.statements)
    again = await create_missing(engine, CORE_SCHEMA, table_prefix=prefix)
    assert again.empty
    # Unknown tables and columns are left alone.
    async with engine.begin() as conn:
        await conn.execute(text("CREATE TABLE mig_unrelated (id INTEGER)"))
        await conn.execute(text("ALTER TABLE mig_user ADD COLUMN legacy TEXT"))
    assert (await create_missing(engine, CORE_SCHEMA, table_prefix=prefix)).empty
    # A plugin adds a table, a nullable column, a defaulted one and a required one.
    extended = merge_schemas(
        CORE_SCHEMA,
        PLUGIN_SCHEMA,
        {
            "session": ModelSchema(
                name="session",
                fields={
                    "level": Field("integer", default=1),
                    "must_fill": Field("string"),
                },
            )
        },
    )
    plan = await create_missing(engine, extended, table_prefix=prefix)
    assert any("CREATE TABLE mig_widget" in s for s in plan.statements)
    assert any("ADD COLUMN nickname" in s for s in plan.statements)
    assert any("ADD COLUMN level" in s and "DEFAULT 1" in s for s in plan.statements)
    assert any("ADD COLUMN must_fill" in s for s in plan.manual)
    remaining = await missing_changes(engine, extended, table_prefix=prefix)
    assert remaining.statements == [] and remaining.manual == plan.manual
    async with engine.connect() as conn:
        tables = await conn.run_sync(
            lambda c: set(__import__("sqlalchemy").inspect(c).get_table_names())
        )
    assert "mig_unrelated" in tables
    await engine.dispose()


def test_dry_run_changes_nothing(tmp_path: object) -> None:
    import asyncio

    async def run() -> None:
        engine = sqlite_memory_engine()
        plan = await create_missing(engine, CORE_SCHEMA, dry_run=True)
        assert plan.statements
        assert not (await missing_changes(engine, CORE_SCHEMA)).empty
        await engine.dispose()

    asyncio.run(run())
