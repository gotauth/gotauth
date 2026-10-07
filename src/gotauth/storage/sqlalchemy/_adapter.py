"""The SQLAlchemy 2 async adapter (CONTRACTS section 3)."""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, TypeVar

from sqlalchemy import Table, delete, event, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from gotauth.contracts.adapter import Adapter, SortBy, Where
from gotauth.contracts.errors import ReferenceViolation, UniqueViolation
from gotauth.contracts.schema import ModelSchema, Schema, default_value, table_name

from ._tables import metadata_for
from ._where import compile_where

__all__ = ["SqlAlchemyAdapter", "sqlalchemy_adapter"]

T = TypeVar("T")
Row = dict[str, Any]  # Any: column values

_PG_KEY = re.compile(r"Key \(([^)]*)\)")
_SQLITE_UNIQUE = re.compile(r"UNIQUE constraint failed: (.+)$", re.MULTILINE)


class _State:
    """What every adapter bound to one engine shares."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self.dialect = engine.dialect.name
        self.sqlite = self.dialect == "sqlite"
        self.schema: dict[str, ModelSchema] = {}
        self.tables: dict[str, Table] = {}
        self.table_prefix = "auth_"
        # SQLite has one writer: operations are serialized per engine. A transaction
        # records its task, so calls made inside it on the root adapter reuse its
        # connection instead of waiting for themselves.
        self.lock = asyncio.Lock()
        self.owner: asyncio.Task[Any] | None = None
        self.tx_conn: AsyncConnection | None = None
        if self.sqlite:
            _sqlite_setup(engine)

    def model(self, name: str) -> tuple[ModelSchema, Table]:
        model = self.schema.get(name)
        if model is None:
            hint = "" if self.schema else " (bind_schema() has not been called)"
            msg = f"unknown model {name!r}{hint}"
            raise ValueError(msg)
        return model, self.tables[name]


def _sqlite_setup(engine: AsyncEngine) -> None:
    """Foreign keys on, case-sensitive LIKE, and real SAVEPOINT support."""
    sync = engine.sync_engine
    if getattr(sync, "_gotauth_sqlite", False):
        return

    @event.listens_for(sync, "connect")
    def _connect(dbapi_connection: Any, _: Any) -> None:  # Any: DBAPI objects
        # The driver's own transaction handling breaks SAVEPOINT; BEGIN is emitted
        # by the "begin" listener instead.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA case_sensitive_like=ON")
        cursor.close()

    @event.listens_for(sync, "begin")
    def _begin(connection: Any) -> None:  # Any: a sync Connection
        connection.exec_driver_sql("BEGIN")

    sync._gotauth_sqlite = True  # type: ignore[attr-defined]


class SqlAlchemyAdapter:
    """Storage on SQLAlchemy 2 async: Postgres (asyncpg) and SQLite (aiosqlite)."""

    id = "sqlalchemy"

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        _state: _State | None = None,
        _conn: AsyncConnection | None = None,
    ) -> None:
        self._state = _state or _State(engine)
        self._conn = _conn

    def __repr__(self) -> str:
        bound = ", in transaction" if self._conn is not None else ""
        return f"SqlAlchemyAdapter({self._state.dialect}{bound})"

    @property
    def engine(self) -> AsyncEngine:
        """The engine (used by the CLI)."""
        return self._state.engine

    @property
    def table_prefix(self) -> str:
        """The table prefix given to ``bind_schema``."""
        return self._state.table_prefix

    def tables(self) -> dict[str, Table]:
        """Tables by logical model name (after ``bind_schema``)."""
        return dict(self._state.tables)

    def bind_schema(self, schema: Schema, *, table_prefix: str = "auth_") -> None:
        """Build the tables of the merged schema."""
        metadata = metadata_for(schema, table_prefix=table_prefix)
        state = self._state
        state.schema = dict(schema)
        state.table_prefix = table_prefix
        state.tables = {
            name: metadata.tables[table_name(model, table_prefix)]
            for name, model in schema.items()
        }

    # ------------------------------------------------------------ connections

    @asynccontextmanager
    async def _connection(self, *, write: bool) -> AsyncGenerator[AsyncConnection]:
        if self._conn is not None:
            async with _savepoint(self._conn, write):
                yield self._conn
            return
        state = self._state
        if state.sqlite:
            current = asyncio.current_task()
            if state.tx_conn is not None and state.owner is current:
                async with _savepoint(state.tx_conn, write):
                    yield state.tx_conn
                return
            async with state.lock, state.engine.begin() as conn:
                yield conn
            return
        async with state.engine.begin() as conn:
            yield conn

    async def _run(
        self,
        model_name: str,
        work: Callable[[AsyncConnection], Awaitable[T]],
        *,
        write: bool,
    ) -> T:
        try:
            async with self._connection(write=write) as conn:
                return await work(conn)
        except IntegrityError as exc:
            raise _translate(model_name, exc) from exc

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[Adapter]:
        """Bind one connection; nested calls reuse it."""
        if self._conn is not None:
            yield self
            return
        state = self._state
        if state.sqlite:
            current = asyncio.current_task()
            if state.tx_conn is not None and state.owner is current:
                yield SqlAlchemyAdapter(state.engine, _state=state, _conn=state.tx_conn)
                return
            async with state.lock, state.engine.begin() as conn:
                state.owner, state.tx_conn = current, conn
                try:
                    yield SqlAlchemyAdapter(state.engine, _state=state, _conn=conn)
                finally:
                    state.owner, state.tx_conn = None, None
            return
        async with state.engine.begin() as conn:
            yield SqlAlchemyAdapter(state.engine, _state=state, _conn=conn)

    # ------------------------------------------------------------ operations

    async def create(self, model: str, data: Mapping[str, Any]) -> Row:
        """Insert a row; missing fields get their defaults."""
        schema, table = self._state.model(model)
        values = _checked(model, schema, data)
        if not isinstance(values.get("id"), str) or not values["id"]:
            msg = f"{model}: ids are supplied by the caller (ctx.ids)"
            raise ValueError(msg)
        for name, field in schema.fields.items():
            if name not in values:
                values[name] = (
                    default_value(field) if field.default is not None else None
                )
            if field.required and values[name] is None:
                msg = f"{model}.{name} is required"
                raise ValueError(msg)

        async def work(conn: AsyncConnection) -> Row:
            result = await conn.execute(
                insert(table).values(values).returning(*table.c)
            )
            return dict(result.mappings().one())

        return await self._run(model, work, write=True)

    async def find_one(self, model: str, where: Sequence[Where]) -> Row | None:
        """Return the first matching row, or ``None``."""
        rows = await self.find_many(model, where, limit=1)
        return rows[0] if rows else None

    async def find_many(
        self,
        model: str,
        where: Sequence[Where] = (),
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort_by: SortBy | None = None,
    ) -> list[Row]:
        """Return matching rows."""
        schema, table = self._state.model(model)
        query = select(table).where(
            compile_where(table, schema, where, self._state.dialect)
        )
        if sort_by is not None:
            column = table.c[sort_by.field]
            query = query.order_by(
                column.desc() if sort_by.direction == "desc" else column
            )
        if limit is not None:
            query = query.limit(limit)
        if offset:
            query = query.offset(offset)

        async def work(conn: AsyncConnection) -> list[Row]:
            result = await conn.execute(query)
            return [dict(row) for row in result.mappings()]

        return await self._run(model, work, write=False)

    async def count(self, model: str, where: Sequence[Where] = ()) -> int:
        """Count matching rows."""
        schema, table = self._state.model(model)
        query = (
            select(func.count())
            .select_from(table)
            .where(compile_where(table, schema, where, self._state.dialect))
        )

        async def work(conn: AsyncConnection) -> int:
            return int((await conn.execute(query)).scalar_one())

        return await self._run(model, work, write=False)

    async def update(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> Row | None:
        """Update at most one row (compare-and-set); return it, or ``None``."""
        schema, table = self._state.model(model)
        values = _checked(model, schema, data)
        condition = compile_where(table, schema, where, self._state.dialect)
        one = select(table.c.id).where(condition).limit(1).scalar_subquery()
        statement = (
            update(table)
            .where(table.c.id == one, condition)
            .values(values)
            .returning(*table.c)
        )

        async def work(conn: AsyncConnection) -> Row | None:
            if not values:
                found = (
                    (await conn.execute(select(table).where(condition).limit(1)))
                    .mappings()
                    .first()
                )
                return dict(found) if found is not None else None
            found = (await conn.execute(statement)).mappings().first()
            return dict(found) if found is not None else None

        return await self._run(model, work, write=True)

    async def update_many(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> int:
        """Update every matching row; return how many."""
        schema, table = self._state.model(model)
        values = _checked(model, schema, data)
        condition = compile_where(table, schema, where, self._state.dialect)

        async def work(conn: AsyncConnection) -> int:
            if not values:
                return int(
                    (
                        await conn.execute(
                            select(func.count()).select_from(table).where(condition)
                        )
                    ).scalar_one()
                )
            return (
                await conn.execute(update(table).where(condition).values(values))
            ).rowcount

        return await self._run(model, work, write=True)

    async def delete(self, model: str, where: Sequence[Where]) -> int:
        """Delete matching rows; return how many."""
        schema, table = self._state.model(model)
        condition = compile_where(table, schema, where, self._state.dialect)

        async def work(conn: AsyncConnection) -> int:
            return (await conn.execute(delete(table).where(condition))).rowcount

        return await self._run(model, work, write=True)


@asynccontextmanager
async def _savepoint(conn: AsyncConnection, write: bool) -> AsyncGenerator[None]:
    """Writes inside a transaction run in a savepoint, so a failed write (for example
    a ``UniqueViolation``) leaves the transaction usable."""
    if not write:
        yield
        return
    async with conn.begin_nested():
        yield


def _checked(model: str, schema: ModelSchema, data: Mapping[str, Any]) -> Row:
    for key in data:
        if key != "id" and key not in schema.fields:
            msg = f"unknown field {model}.{key}"
            raise ValueError(msg)
    return dict(data)


def _translate(model: str, exc: IntegrityError) -> Exception:
    """Map a database integrity error to the contract errors."""
    orig: Any = exc.orig  # Any: the driver's exception
    cause: Any = getattr(orig, "__cause__", None)  # Any: asyncpg's exception
    sqlstate = getattr(orig, "sqlstate", None) or getattr(cause, "sqlstate", None)
    text = str(orig)
    detail = str(getattr(cause, "detail", "") or getattr(orig, "detail", "") or "")
    if sqlstate == "23505" or "UNIQUE constraint failed" in text:
        return UniqueViolation(model, _unique_fields(text, detail))
    if sqlstate == "23503" or "FOREIGN KEY constraint failed" in text:
        match = _PG_KEY.search(detail)
        fields = tuple(f.strip() for f in match.group(1).split(",")) if match else ()
        return ReferenceViolation(model, fields)
    return exc


def _unique_fields(text: str, detail: str) -> tuple[str, ...]:
    match = _PG_KEY.search(detail)
    if match:
        return tuple(part.strip().strip('"') for part in match.group(1).split(","))
    match = _SQLITE_UNIQUE.search(text)
    if match:
        return tuple(part.strip().split(".")[-1] for part in match.group(1).split(","))
    return ()


def sqlalchemy_adapter(engine: AsyncEngine) -> SqlAlchemyAdapter:
    """Return the adapter for an async engine (CONTRACTS 13.2).

    Postgres: ``create_async_engine("postgresql+asyncpg://...")``. SQLite:
    ``create_async_engine("sqlite+aiosqlite:///auth.db")``; for ``:memory:`` pass
    ``poolclass=StaticPool`` so every operation sees the same database.
    """
    return SqlAlchemyAdapter(engine)
