"""DDL output and additive migrations (``gotauth generate --sql`` and ``migrate``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Column, Connection, Dialect, MetaData, Table, inspect, text
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.schema import CreateColumn, CreateIndex, CreateTable

from gotauth.contracts.schema import Schema, table_name

from ._tables import metadata_for

__all__ = ["MigrationPlan", "create_missing", "missing_changes", "schema_ddl"]

_DIALECTS: dict[str, Dialect] = {
    "postgresql": postgresql.dialect(),  # pyright: ignore[reportUnknownMemberType]
    "sqlite": sqlite.dialect(),  # pyright: ignore[reportUnknownMemberType]
}


def _dialect(name: str) -> Dialect:
    try:
        return _DIALECTS[name]
    except KeyError:
        msg = f"unsupported dialect {name!r}; use postgresql or sqlite"
        raise ValueError(msg) from None


def _create_table(table: Table, dialect: Dialect) -> list[str]:
    statements = [str(CreateTable(table).compile(dialect=dialect)).strip() + ";"]
    statements.extend(
        str(CreateIndex(index).compile(dialect=dialect)).strip() + ";"
        for index in sorted(table.indexes, key=lambda i: str(i.name))
    )
    return statements


def schema_ddl(schema: Schema, *, dialect: str, table_prefix: str = "auth_") -> str:
    """Return ``CREATE TABLE`` and ``CREATE INDEX`` statements for an empty database."""
    metadata = metadata_for(schema, table_prefix=table_prefix)
    target = _dialect(dialect)
    return (
        "\n\n".join(
            statement
            for table in metadata.sorted_tables
            for statement in _create_table(table, target)
        )
        + "\n"
    )


@dataclass
class MigrationPlan:
    """What ``migrate`` would do.

    Attributes:
        statements: SQL that ``migrate`` runs: missing tables, then missing nullable
            or defaulted columns.
        manual: SQL it never runs: required columns without a default. Review and
            run them by hand.
    """

    statements: list[str] = field(default_factory=list[str])
    manual: list[str] = field(default_factory=list[str])
    tables: list[Table] = field(default_factory=list[Table])

    @property
    def empty(self) -> bool:
        """True when the database already matches."""
        return not self.statements and not self.manual


def _literal(value: object, dialect: Dialect) -> str | None:
    if isinstance(value, bool):
        if dialect.name == "postgresql":
            return "true" if value else "false"
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return None


def _add_column(
    table: Table, column: Column[Any], dialect: Dialect, default: object
) -> tuple[list[str], bool]:
    """Return the statements to add a column and whether migrate may run them."""
    spec = str(CreateColumn(column).compile(dialect=dialect)).strip()
    # UNIQUE on ADD COLUMN is not portable: a unique index follows instead.
    spec = spec.replace(" UNIQUE", "")
    for key in column.foreign_keys:
        # SQLite allows REFERENCES on ADD COLUMN when the column may be NULL.
        target = key.column
        action = f" ON DELETE {key.ondelete}" if key.ondelete else ""
        spec += f" REFERENCES {target.table.name} ({target.name}){action}"
    literal = _literal(default, dialect)
    automatic = column.nullable or literal is not None
    if not column.nullable and literal is not None:
        spec += f" DEFAULT {literal}"
    statements = [f"ALTER TABLE {table.name} ADD COLUMN {spec};"]
    if column.unique:
        statements.append(
            f"CREATE UNIQUE INDEX uq_{table.name}_{column.name} "
            f"ON {table.name} ({column.name});"
        )
    elif column.index:
        name = f"ix_{table.name}_{column.name}"
        statements.append(f"CREATE INDEX {name} ON {table.name} ({column.name});")
    return statements, bool(automatic)


def _plan(
    conn: Connection, schema: Schema, metadata: MetaData, table_prefix: str
) -> MigrationPlan:
    inspector = inspect(conn)
    existing = set(inspector.get_table_names())
    plan = MigrationPlan()
    by_table = {table_name(model, table_prefix): model for model in schema.values()}
    for table in metadata.sorted_tables:
        if table.name not in existing:
            plan.tables.append(table)
            plan.statements.extend(_create_table(table, conn.dialect))
            continue
        present = {column["name"] for column in inspector.get_columns(table.name)}
        model = by_table[table.name]
        for column in table.columns:
            if column.name in present:
                continue
            spec = model.fields.get(column.name)
            default = (
                spec.default
                if spec is not None and not callable(spec.default)
                else None
            )
            statements, automatic = _add_column(table, column, conn.dialect, default)
            (plan.statements if automatic else plan.manual).extend(statements)
        plan.statements.extend(_missing_unique_groups(inspector, table, model))
    return plan


def _missing_unique_groups(
    inspector: Any, table: Table, model: Any
) -> list[str]:  # Any: SQLAlchemy inspector, ModelSchema
    """Unique indexes for ``unique_together`` groups the table does not enforce yet."""
    enforced = {
        tuple(sorted(c for c in item["column_names"] if c))
        for item in [
            *inspector.get_unique_constraints(table.name),
            *(i for i in inspector.get_indexes(table.name) if i.get("unique")),
        ]
    }
    statements: list[str] = []
    for group in model.unique_together:
        if tuple(sorted(group)) in enforced:
            continue
        name = f"uq_{table.name}_{'_'.join(group)}"
        statements.append(
            f"CREATE UNIQUE INDEX {name} ON {table.name} ({', '.join(group)});"
        )
    return statements


async def missing_changes(
    engine: AsyncEngine, schema: Schema, *, table_prefix: str = "auth_"
) -> MigrationPlan:
    """Compare the database with the schema. Unknown tables and columns are ignored."""
    metadata = metadata_for(schema, table_prefix=table_prefix)
    async with engine.connect() as conn:
        return await conn.run_sync(_plan, schema, metadata, table_prefix)


async def create_missing(
    engine: AsyncEngine,
    schema: Schema,
    *,
    table_prefix: str = "auth_",
    dry_run: bool = False,
) -> MigrationPlan:
    """Create missing tables and nullable or defaulted columns; never drop or alter.

    Returns the plan; ``plan.manual`` lists the SQL left for a person to run.
    """
    plan = await missing_changes(engine, schema, table_prefix=table_prefix)
    if dry_run or not plan.statements:
        return plan
    async with engine.begin() as conn:
        for statement in plan.statements:
            await conn.execute(text(statement.rstrip(";")))
    return plan
