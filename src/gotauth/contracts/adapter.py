"""CONTRACTS section 3: the storage adapter interface.

Rules every adapter follows (``gotauth.testing.adapter_conformance`` checks them):

- Keys are logical field names; the adapter maps them to tables and columns.
- Ids are always supplied by the caller (``ctx.ids``).
- ``update`` changes at most one row and returns it, or ``None``. Callers use it as
  compare-and-set by putting the expected current state in ``where``.
- ``delete`` returns the number of rows removed and applies ``Reference.on_delete``.
- ``string_list`` and ``json`` round-trip as lists and objects; ``datetime``
  round-trips as aware UTC. Naive datetimes are rejected with ``ValueError``.
- ``transaction()`` gives an adapter whose operations commit or roll back together;
  nested calls on that adapter reuse the outer transaction.
- Unique violations raise ``UniqueViolation``; broken references raise
  ``ReferenceViolation``.
- ``Field.default`` fills missing fields on create.
- ``sort_by`` ties break by ``id`` in the same direction (CCR 013).

``Where`` semantics: clauses are grouped by ``connector`` with ``and`` binding
tighter than ``or``; ``eq None`` is IS NULL and ``ne None`` is IS NOT NULL; ``ne``
and ``not_in`` with a value also match NULL rows; ``contains`` is a substring test
on string fields and a membership test on ``string_list`` fields; ``is_null`` takes
``True`` or ``False``.
Unknown models, unknown fields and unsupported operator and type pairs raise
``ValueError``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    Protocol,
    TypeAlias,
    cast,
    get_args,
    runtime_checkable,
)

if TYPE_CHECKING:
    from gotauth.contracts.schema import Schema

__all__ = ["WHERE_OPS", "Adapter", "SortBy", "Where", "WhereOp"]

WhereOp: TypeAlias = Literal[
    "eq",
    "ne",
    "lt",
    "lte",
    "gt",
    "gte",
    "in",
    "not_in",
    "contains",
    "starts_with",
    "ends_with",
    "is_null",
]
WHERE_OPS: tuple[WhereOp, ...] = cast("tuple[WhereOp, ...]", get_args(WhereOp))


@dataclass(frozen=True)
class Where:
    """One condition of a query.

    Attributes:
        field: Logical field name.
        value: The value to compare with; a list for ``in`` and ``not_in``, a bool for
            ``is_null``.
        op: The operator.
        connector: How this clause joins the previous one. Ignored on the first clause.
    """

    field: str
    value: Any = None  # Any: the value type follows the field type
    op: WhereOp = "eq"
    connector: Literal["and", "or"] = "and"


@dataclass(frozen=True)
class SortBy:
    """Sort order for ``find_many``."""

    field: str
    direction: Literal["asc", "desc"] = "asc"


@runtime_checkable
class Adapter(Protocol):
    """Storage for the merged schema. Rows are dicts keyed by logical field names."""

    id: str
    """Adapter name, e.g. ``"memory"`` or ``"sqlalchemy"``."""

    async def create(self, model: str, data: Mapping[str, Any]) -> dict[str, Any]:
        """Insert a row (``data`` includes ``id``) and return the stored row."""
        ...

    async def find_one(
        self, model: str, where: Sequence[Where]
    ) -> dict[str, Any] | None:
        """Return the first matching row, or ``None``."""
        ...

    async def find_many(
        self,
        model: str,
        where: Sequence[Where] = (),
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort_by: SortBy | None = None,
    ) -> list[dict[str, Any]]:
        """Return the matching rows."""
        ...

    async def count(self, model: str, where: Sequence[Where] = ()) -> int:
        """Return the number of matching rows."""
        ...

    async def update(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        """Update at most one matching row; return it, or ``None`` if none matched."""
        ...

    async def update_many(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> int:
        """Update every matching row; return how many were updated."""
        ...

    async def delete(self, model: str, where: Sequence[Where]) -> int:
        """Delete the matching rows; return how many were deleted."""
        ...

    def transaction(self) -> AbstractAsyncContextManager[Adapter]:
        """Return a context manager yielding an adapter bound to one transaction."""
        ...

    def bind_schema(self, schema: Schema, *, table_prefix: str = "auth_") -> None:
        """Bind the merged schema. ``GotAuth(...)`` calls it once."""
        ...
