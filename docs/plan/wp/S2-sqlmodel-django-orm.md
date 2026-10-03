# S2: SQLModel models + Django ORM adapter

| | |
|---|---|
| Lane / wave | Storage / **Wave 4** (only on request) |
| Size | M each: S2a SQLModel, S2b Django ORM |
| Depends on | S1 (SQLAlchemy adapter, `gotauth generate`), F2 (`adapter_conformance`) |
| Can start | after M3, once public requests exist (Notes) |
| Write scope | `src/gotauth/storage/sqlmodel/**`, `src/gotauth/storage/django/**`, `tests/storage/sqlmodel/**`, `tests/storage/django/**`, `changes/S2*.md`, `docs/requests/S2-*.md`, `docs/ccr/*-sqlmodel-extra.md` |
| Allowed new deps | S2b: `django` behind the existing `django` extra (CONTRACTS section 0, Phase 4). S2a: `sqlmodel` behind the `sqlmodel` extra (CONTRACTS section 0, Phase 4). Only F1-owned `pyproject.toml` declares extras: file `docs/requests/S2-extras.md`. Nothing in core |

## Goal
Let apps on SQLModel or Django's ORM join their own tables to GotAuth's tables and keep using their ORM.

## Build
- **S2a SQLModel:** `generate_sqlmodel(schema, *, table_prefix="auth_") -> str` writes `table=True` classes for the merged schema (section 2) with S1's table and column names (`ModelSchema.table`, else `table_prefix + name`), `unique_together` as `UniqueConstraint`, foreign keys and relationships from `Reference`, and `returned=False` fields excluded from default serialization. Runtime storage stays S1's adapter (SQLModel is SQLAlchemy). CLI wiring (`gotauth generate --orm sqlmodel`) via a request (S1 owns the CLI).
- **S2b Django ORM adapter** implementing section 3: models generated into an installable Django app (`makemigrations` works) with `db_table` following the same naming rule and `bind_schema(schema, *, table_prefix="auth_")` checking that the generated models match; `Where` / `SortBy` -> `Q` and `order_by`; `IntegrityError` (incl. `unique_together`) -> `UniqueViolation(model, fields)`; compare-and-set `update` via `filter(...).aupdate(...) == 1`; `delete` count from `adelete()`; `on_delete` CASCADE / SET_NULL / RESTRICT from `Reference`.
- Ids are opaque strings supplied by the caller (section 1; imported rows may keep UUIDs): `CharField(primary_key=True, max_length=64)`, never an auto field.
- Django async limits: async query methods exist (`aget`, `acreate`, `aupdate`, `adelete`, `acount`, async iteration), but transactions have no async API. `transaction()` runs its operations inside one `sync_to_async(thread_sensitive=True)` block with `transaction.atomic`. Document the cost.

## Acceptance tests
- Both pass `adapter_conformance()` on SQLite and Postgres (S2a through S1's adapter).
- Generated SQLModel classes produce the same DDL as S1's migration for the full plugin schema, default and custom `table_prefix`.
- A test app joins `user` to an app table with each ORM.

## Out of scope
Django framework integration (A3), Alembic (S1), MySQL.

## Notes
- Gate: >= 3 independent public requests per ORM (GitHub issues, discussions or posts).
- The `django` extra is shared with A3; coordinate the request so it is added once.
- Target Django 5.2 LTS or newer and the current SQLModel; check Django's async ORM and transaction docs and record versions.
