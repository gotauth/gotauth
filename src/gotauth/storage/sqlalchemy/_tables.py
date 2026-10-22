"""SQLAlchemy tables for a GotAuth schema."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Dialect,
    ForeignKey,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator, TypeEngine

from gotauth.contracts.schema import Field, ModelSchema, Schema, table_name

__all__ = ["NAMING_CONVENTION", "UtcDateTime", "metadata_for"]

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
"""Stable constraint names, so migrations do not churn."""

_ON_DELETE = {"cascade": "CASCADE", "set_null": "SET NULL", "restrict": "RESTRICT"}


class UtcDateTime(TypeDecorator[datetime]):
    """Stores aware datetimes as UTC and always returns aware UTC.

    SQLite keeps no time zone, so values are stored as naive UTC there.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self, value: datetime | None, dialect: Dialect
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            msg = "naive datetimes are not allowed; use timezone-aware UTC"
            raise ValueError(msg)
        value = value.astimezone(UTC)
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(
        self, value: datetime | None, dialect: Dialect
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def _json() -> TypeEngine[Any]:  # Any: JSON values
    return JSON().with_variant(JSONB(), "postgresql")


def _column_type(field: Field) -> TypeEngine[Any]:  # Any: column values
    match field.type:
        case "string":
            return String(field.max_length) if field.max_length else Text()
        case "text":
            return Text()
        case "integer":
            return BigInteger()
        case "boolean":
            return Boolean()
        case "datetime":
            return UtcDateTime()
        case "json" | "string_list":
            return _json()


def _column(name: str, field: Field, schema: Schema, table_prefix: str) -> Column[Any]:
    args: list[Any] = []
    # A reference to a model outside the schema (for example oauth_client.agent_id
    # without the agent plugin) is a plain column, as in the memory adapter.
    if field.references is not None and field.references.model in schema:
        target = schema[field.references.model]
        args.append(
            ForeignKey(
                f"{table_name(target, table_prefix)}.{field.references.field}",
                ondelete=_ON_DELETE[field.references.on_delete],
            )
        )
    return Column(
        name,
        _column_type(field),
        *args,
        nullable=not field.required,
        unique=field.unique or None,
        index=(field.index and not field.unique) or None,
        server_default=_server_default(field),
    )


def _server_default(field: Field) -> Any:  # Any: a SQLAlchemy default expression
    """The database default for a NOT NULL column whose field has a constant default.

    A plugin may add such a field to a table that already has rows (``two_factor()``
    adds ``user.two_factor_enabled``); without a database default, the generated
    ``add_column`` fails on those rows (issue #53). Callable defaults have none, and
    neither have unique fields (every row would get the same value): such fields must
    be nullable when they join an existing table.

    Booleans are the SQL keywords ``true`` and ``false``, not SQLAlchemy's
    ``true()``, which compiles to ``1`` on SQLite: a revision generated against SQLite
    must also run on Postgres. SQLite reads the keywords since 3.23.
    """
    value = field.default
    if not field.required or field.unique or value is None or callable(value):
        return None
    if isinstance(value, bool):
        if field.type != "boolean":
            return None
        return text("true" if value else "false")
    if isinstance(value, int) and field.type == "integer":
        return text(str(value))
    if isinstance(value, str) and field.type in ("string", "text"):
        return value
    return None


def metadata_for(schema: Schema, *, table_prefix: str = "auth_") -> MetaData:
    """Return SQLAlchemy ``MetaData`` with one table per model.

    For Alembic ``env.py``: ``target_metadata = metadata_for(auth.schema,
    table_prefix=auth.config.advanced.table_prefix)``.
    """
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    for model in schema.values():
        _table(metadata, model, schema, table_prefix)
    return metadata


def _table(
    metadata: MetaData, model: ModelSchema, schema: Schema, table_prefix: str
) -> Table:
    columns: list[Any] = [Column("id", String(64), primary_key=True)]
    columns.extend(
        _column(name, field, schema, table_prefix)
        for name, field in model.fields.items()
    )
    columns.extend(UniqueConstraint(*group) for group in model.unique_together)
    return Table(table_name(model, table_prefix), metadata, *columns)
