"""CONTRACTS section 2: the schema plugins extend and adapters read."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias, cast, get_args

from gotauth.contracts.errors import SchemaConflictError

__all__ = [
    "FIELD_TYPES",
    "Field",
    "FieldType",
    "ModelSchema",
    "OnDelete",
    "Reference",
    "Schema",
    "default_value",
    "merge_schemas",
    "returned_only",
    "table_name",
]

FieldType: TypeAlias = Literal[
    "string", "text", "integer", "boolean", "datetime", "json", "string_list"
]
FIELD_TYPES: tuple[FieldType, ...] = cast("tuple[FieldType, ...]", get_args(FieldType))

OnDelete: TypeAlias = Literal["cascade", "set_null", "restrict"]


@dataclass(frozen=True)
class Reference:
    """A foreign key to another model.

    Attributes:
        model: Logical name of the referenced model, e.g. ``"user"``.
        field: Referenced field, ``"id"`` by default.
        on_delete: What happens to referencing rows when the referenced row is deleted.
    """

    model: str
    field: str = "id"
    on_delete: OnDelete = "cascade"


@dataclass(frozen=True)
class Field:
    """One field of a model.

    Attributes:
        type: The storage type.
        required: False allows NULL.
        unique: NULL values never collide.
        index: Create an index.
        references: A foreign key, if any.
        default: A value or a zero-argument callable, applied on create when the
            field is missing. Applied in Python (by the adapter), never by the database.
        returned: False keeps the field out of record models and API output.
        input: False means clients can't set it.
        max_length: Maximum string length, if any.
    """

    type: FieldType
    required: bool = True
    unique: bool = False
    index: bool = False
    references: Reference | None = None
    # Any: a default may be a value of any field type, or a factory for one.
    default: Any | Callable[[], Any] | None = None
    returned: bool = True
    input: bool = True
    max_length: int | None = None


@dataclass(frozen=True)
class ModelSchema:
    """A model: its fields and table options.

    Attributes:
        name: Logical name, e.g. ``"session"``.
        fields: Fields by name. ``"id"`` (a string primary key) is implicit and never
            listed.
        unique_together: Groups of fields that are unique together.
        table: Table name; by default ``advanced.table_prefix + name``.
    """

    name: str
    fields: Mapping[str, Field]
    unique_together: tuple[tuple[str, ...], ...] = ()
    table: str | None = None


Schema: TypeAlias = Mapping[str, ModelSchema]
"""Models by logical name."""


def merge_schemas(base: Schema, *extra: Schema) -> Schema:
    """Merge plugin schemas into a base schema.

    New models and new fields on existing models are added. Redefining a field, even
    identically, listing ``"id"``, or giving an existing model a different table name
    raises :class:`SchemaConflictError`. ``unique_together`` groups are combined.

    Args:
        base: The base schema, e.g. ``CORE_SCHEMA``.
        *extra: Schemas to add, in order.

    Returns:
        A new schema; the inputs are not modified.

    Raises:
        SchemaConflictError: On any conflict described above.
    """
    merged: dict[str, ModelSchema] = {}
    for schema in (base, *extra):
        for key, model in schema.items():
            _check_model(key, model)
            current = merged.get(key)
            if current is None:
                merged[key] = ModelSchema(
                    name=model.name,
                    fields=dict(model.fields),
                    unique_together=model.unique_together,
                    table=model.table,
                )
                continue
            if model.table is not None and model.table != current.table:
                msg = f"model {key!r} is given a second table name {model.table!r}"
                raise SchemaConflictError(msg)
            fields = dict(current.fields)
            for field_name, field in model.fields.items():
                if field_name in fields:
                    msg = f"field {key}.{field_name} is defined twice"
                    raise SchemaConflictError(msg)
                fields[field_name] = field
            groups = list(current.unique_together)
            groups.extend(
                group for group in model.unique_together if group not in groups
            )
            merged[key] = ModelSchema(
                name=current.name,
                fields=fields,
                unique_together=tuple(groups),
                table=current.table,
            )
    return merged


def _check_model(key: str, model: ModelSchema) -> None:
    if model.name != key:
        msg = f"model registered as {key!r} is named {model.name!r}"
        raise SchemaConflictError(msg)
    if "id" in model.fields:
        msg = f"model {key!r} lists 'id', which is implicit"
        raise SchemaConflictError(msg)


def returned_only(model: ModelSchema, row: Mapping[str, Any]) -> dict[str, Any]:
    """Drop the fields with ``returned=False`` from a row.

    Use it before turning an adapter row into a record or response model (section 2.2).

    Args:
        model: The row's model.
        row: An adapter row.

    Returns:
        A new dict without the hidden fields. Unknown keys are kept.
    """
    hidden = {name for name, field in model.fields.items() if not field.returned}
    return {key: value for key, value in row.items() if key not in hidden}


def table_name(model: ModelSchema, table_prefix: str = "auth_") -> str:
    """Return the table name of a model: ``model.table`` or ``table_prefix + name``."""
    return model.table if model.table is not None else table_prefix + model.name


def default_value(field: Field) -> Any:  # Any: the value of any field type
    """Return the default of a field, calling it when it is a factory."""
    default = field.default
    if callable(default):
        return cast("Callable[[], Any]", default)()
    return default
