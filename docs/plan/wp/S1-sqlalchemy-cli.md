# S1: SQLAlchemy adapter, Alembic, gotauth CLI

| | |
|---|---|
| Lane / wave | Storage / **Wave 1** |
| Size | L (3-4 agent-days) |
| Depends on | M0 |
| Can start | after M0 |
| Write scope | `src/gotauth/storage/sqlalchemy/**`, `src/gotauth/cli/**`, `tests/storage/sqlalchemy/`, `tests/cli/`, `changes/S1.*.md` |
| Allowed new deps | none (sqlalchemy[asyncio], alembic, asyncpg, aiosqlite are existing extras, imported lazily) |

## Goal
Production storage on Postgres and SQLite that passes the same conformance suite as the memory adapter, plus the `gotauth` CLI that creates and migrates the schema.

## Build
- `sqlalchemy_adapter(engine: AsyncEngine) -> Adapter` (13.2; `id = "sqlalchemy"`), following every rule of CONTRACTS section 3.
- `bind_schema(schema, *, table_prefix="auth_")` (C1 passes `advanced.table_prefix`) builds one `MetaData` (with a naming convention, so constraint names are stable) and a `Table` per model: `ModelSchema.table` if set, else `table_prefix + name` (`auth_user`, `auth_session`, ...). `metadata_for(schema, *, table_prefix="auth_")` is public for Alembic `env.py`.
  - `id`: String(64) primary key, an opaque string (imported rows may keep UUIDs, section 1). string -> `String(max_length)`, or Text when unset; text -> Text; integer -> BigInteger; boolean -> Boolean; datetime -> `DateTime(timezone=True)` through a TypeDecorator that stores UTC and returns aware UTC (SQLite keeps no zone); json and string_list -> JSON, JSONB on Postgres.
  - `unique` (NULLs allowed more than once, e.g. `oauth_token.refresh_token_hash`), `index`, `unique_together` -> UniqueConstraint, and `references` -> ForeignKey with `ondelete` CASCADE / SET NULL / RESTRICT.
- Where -> SQL with the conformance semantics: `eq`/`ne` None -> IS NULL / IS NOT NULL; empty `in` / `not_in`; `contains` (escaped LIKE on strings; JSONB `@>` on Postgres, `json_each` on SQLite for string_list); `starts_with` / `ends_with` with escaped LIKE; `and` binds tighter than `or`.
- `update` is compare-and-set on at most one row: `UPDATE t SET ... WHERE id = (SELECT id FROM t WHERE <where> LIMIT 1) AND <where> RETURNING *`. MySQL has no RETURNING and is on the cut list: build its select-then-update fallback only if asked.
- `delete` returns `rowcount`. `transaction()` binds one AsyncConnection; nested calls reuse it. Unique IntegrityError -> `UniqueViolation(model, fields)`, mapping the constraint name (or SQLite's message) back to fields.
- SQLite: `PRAGMA foreign_keys=ON` on every connection (event listener), StaticPool for `:memory:`. Postgres through asyncpg.
- CLI, console script `gotauth` (set up by F1), argparse only, `main(argv=None) -> int`. Importing `gotauth.cli` loads no extras, so `uvx gotauth check` works bare (G3).
  - `--auth module:attr` (default `auth:auth`) imports the user's GotAuth from the CWD; a missing extra prints the `pip install "gotauth[sqlalchemy]"` hint.
  - `init [--dir .] [--database-url URL] [--force]`: writes an `auth.py` template (SQLAlchemy adapter, secret from env), adds `GOTAUTH_SECRET=<new>` to `.env` (never overwrites an existing value; mode 0600 on POSIX), prints the FastAPI snippet (router include at `base_path`, `app.mount("/", auth.well_known())` last). Never prompts.
  - `generate [--sql --dialect postgresql|sqlite] [-m MESSAGE]`: an Alembic revision for `auth.schema` (autogenerate against the configured database), or DDL to stdout with `--sql`.
  - `migrate [--dry-run]`: creates missing tables and nullable or defaulted columns only. Never drops or alters; other changes are printed as SQL to run by hand.
  - `secret`: prints a new 43-char secret from the crypto kit.
  - `check` -> `gotauth.checkup.main(argv)` (G3); `import` -> `gotauth.importers.fastapi_users.main(argv)` (I1). Lazy imports; if missing, print "not available in this version" and exit 2.

## Acceptance tests
- `adapter_conformance` passes on SQLite (aiosqlite, file and `:memory:`) and Postgres (compose service, `postgres` marker, required in CI).
- On Postgres, 20 concurrent compare-and-set updates and 20 concurrent single-use deletes -> exactly 1 success each.
- The generated migration applies, downgrades and re-applies on SQLite and Postgres; `--sql` output runs on an empty database.
- A test plugin adding a model and a `user` field gets its table and column generated; tables carry the default `auth_` prefix, a custom `table_prefix` and an explicit `ModelSchema.table`.
- `migrate` twice is a no-op; unknown tables and columns in the database are left alone.
- Round trips: non-UTC aware datetimes come back as UTC, json, string_list, unicode.
- Deleting a user cascades to sessions and accounts on both dialects.
- CLI via `main([...])` in `tmp_path`: `init` does not overwrite, `.env` secret >= 32 chars, `check` without G3 exits 2.

## Out of scope
- SQLModel and Django ORM (S2); MySQL (cut list); importer (I1); checkup rules (G3).

## Notes
- Check the current SQLAlchemy 2.x and Alembic docs (`produce_migrations`, `render_python_code`, autogenerate); record versions in the module README.
- The C1-owned `rate_limit` model (ids `rlt`) is in `auth.schema` only with `rate_limit.storage="database"`; `generate` and `migrate` just follow `auth.schema`.
