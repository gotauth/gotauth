"""``Where`` clauses to SQL, with the conformance suite's semantics."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import (
    ColumnElement,
    Table,
    and_,
    exists,
    false,
    func,
    literal,
    or_,
    select,
    true,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import cast as sql_cast

from gotauth.contracts.adapter import Where
from gotauth.contracts.schema import ModelSchema

__all__ = ["compile_where"]


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _column(table: Table, model: ModelSchema, field: str) -> Any:  # Any: a column
    if field != "id" and field not in model.fields:
        msg = f"unknown field {model.name}.{field}"
        raise ValueError(msg)
    return table.c[field]


def _clause(
    table: Table, model: ModelSchema, clause: Where, dialect: str
) -> ColumnElement[bool]:
    column = _column(table, model, clause.field)
    value = clause.value
    match clause.op:
        case "eq":
            return column.is_(None) if value is None else column == value
        case "ne":
            return column.is_not(None) if value is None else column != value
        case "lt":
            return column < value
        case "lte":
            return column <= value
        case "gt":
            return column > value
        case "gte":
            return column >= value
        case "in":
            return column.in_(list(value)) if value else false()
        case "not_in":
            return column.not_in(list(value)) if value else true()
        case "is_null":
            return column.is_(None) if value else column.is_not(None)
        case "contains":
            field_type = model.fields[clause.field].type if clause.field != "id" else ""
            if field_type == "string_list":
                return _list_contains(column, str(value), dialect)
            return column.like(f"%{_escape(str(value))}%", escape="\\")
        case "starts_with":
            return column.like(f"{_escape(str(value))}%", escape="\\")
        case "ends_with":
            return column.like(f"%{_escape(str(value))}", escape="\\")


def _list_contains(
    column: Any, value: str, dialect: str
) -> ColumnElement[bool]:  # Any: a column
    if dialect == "postgresql":
        return sql_cast(column, JSONB).contains([value])
    items = func.json_each(column).table_valued("value")
    return exists(select(literal(1)).select_from(items).where(items.c.value == value))


def compile_where(
    table: Table, model: ModelSchema, where: Sequence[Where], dialect: str
) -> ColumnElement[bool]:
    """Return the SQL condition: ``and`` binds tighter than ``or``."""
    if not where:
        return true()
    groups: list[list[ColumnElement[bool]]] = [[]]
    for index, clause in enumerate(where):
        if index > 0 and clause.connector == "or":
            groups.append([])
        groups[-1].append(_clause(table, model, clause, dialect))
    return or_(*(and_(*group) for group in groups))
