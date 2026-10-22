# gotauth.storage.sqlalchemy

Production storage on SQLAlchemy 2 (async): Postgres through asyncpg and SQLite through
aiosqlite. Work package S1. Built and tested against SQLAlchemy 2.1.3, Alembic 1.20.0,
asyncpg 0.31.0 (2026-10-07).

```python
from sqlalchemy.ext.asyncio import create_async_engine
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

engine = create_async_engine("postgresql+asyncpg://user:pass@host/db")
auth = GotAuth(database=sqlalchemy_adapter(engine), ...)
```

For SQLite `:memory:`, pass `poolclass=StaticPool` so every operation sees the same
database.

## Tables

One table per model: `ModelSchema.table` when set, else `advanced.table_prefix + name`
(`auth_user`, `auth_session`, ...). `metadata_for(auth.schema, table_prefix=...)` returns
the `MetaData`, for an Alembic `env.py`. Constraint names follow `NAMING_CONVENTION`, so
migrations stay stable.

| Field type | Column |
|---|---|
| `id` | `String(64)` primary key |
| `string` | `String(max_length)`, or `Text` without a length |
| `text` | `Text` |
| `integer` | `BigInteger` |
| `boolean` | `Boolean` |
| `datetime` | `DateTime(timezone=True)`; stored as UTC, always returned aware UTC (naive values are rejected) |
| `json`, `string_list` | `JSON`, `JSONB` on Postgres |

## Behaviour

- Everything in CONTRACTS section 3; the shared conformance suite runs on Postgres,
  SQLite files and SQLite `:memory:`.
- `update` is a compare-and-set on at most one row
  (`UPDATE ... WHERE id = (SELECT id ... LIMIT 1) AND <where> RETURNING *`).
- Inside `transaction()`, every write runs in a savepoint, so a `UniqueViolation` leaves
  the transaction usable (CCR 001).
- `UniqueViolation.fields` comes from the database message (Postgres `Key (...)`,
  SQLite `UNIQUE constraint failed`), not from constraint names that Postgres may
  truncate.
- SQLite: foreign keys on, case-sensitive `LIKE`, real `SAVEPOINT` support. SQLite has
  one writer, so operations on one engine are serialized; calls made inside a
  transaction on the same task reuse its connection.
- Inside a transaction, use the adapter that `transaction()` yields (`ctx.adapter` in
  handlers). On Postgres the root adapter opens a separate connection and commits on its
  own; if it touches a row the transaction has locked, it waits for that transaction.
- `ne`, `in` and `not_in` treat NULL like the memory adapter: NULL differs from every
  value, and a `None` option matches NULL rows. Sorting puts NULLs first ascending and
  last descending on every backend.

## Migrations

- `gotauth migrate` creates missing tables and missing nullable or defaulted columns. It
  never drops or alters; required columns without a default are printed as SQL to run
  by hand. Tables and columns it does not know are left alone.
- `gotauth generate` writes an Alembic revision for GotAuth's tables only (other tables
  in the database are ignored). Set up Alembic first with `alembic init -t async
  migrations`.
- **Defaults in the database:** a required field with a constant default (a bool, int
  or string, such as `two_factor()`'s `user.two_factor_enabled = False`) gets a matching
  `server_default`, so a revision that adds it to a table with rows works on Postgres
  and SQLite. Booleans use the SQL keywords `true` and `false`, so a revision generated
  on SQLite also runs on Postgres. A field with a callable default (`default=list`) or a
  unique one has none: a plugin that adds one to an existing table must make it
  nullable. `gotauth migrate` uses the same defaults. `gotauth generate` does not
  compare server defaults, so tables created before this change get no new revision
  for them.
- `gotauth generate --sql --dialect postgresql|sqlite` prints the DDL for an empty
  database.
