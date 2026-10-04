"""The in-memory adapter: CONTRACTS section 3 semantics without a database."""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import AsyncGenerator, Callable, Iterable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypeVar, cast

from gotauth.contracts.errors import ConfigError, ReferenceViolation, UniqueViolation
from gotauth.contracts.schema import (
    Field,
    ModelSchema,
    Reference,
    Schema,
    default_value,
    table_name,
)

if TYPE_CHECKING:
    from gotauth.contracts.adapter import Adapter, SortBy, Where

__all__ = ["MemoryAdapter", "memory_adapter"]

Row = dict[str, Any]  # Any: field values of every field type
T = TypeVar("T")

_ID_FIELD = Field("string", unique=True)
_TEXT = frozenset({"string", "text"})
_ORDERED = frozenset({"string", "text", "integer", "datetime"})
_SCALAR = frozenset({"string", "text", "integer", "boolean", "datetime"})
_OPS = frozenset(
    {
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
    }
)


@dataclass(frozen=True)
class _Referrer:
    model: str
    field: str
    reference: Reference


@dataclass
class _Store:
    """Tables and the bound schema, shared by the root adapter and its transactions.

    Every method is synchronous, so each operation is atomic on the event loop. Stored
    rows are never mutated in place: writes replace them, which keeps snapshots cheap.
    """

    schema: dict[str, ModelSchema] = field(default_factory=dict[str, ModelSchema])
    tables: dict[str, dict[str, Row]] = field(default_factory=dict[str, dict[str, Row]])
    referrers: dict[str, list[_Referrer]] = field(
        default_factory=dict[str, list[_Referrer]]
    )
    table_prefix: str = "auth_"

    # --------------------------------------------------------------- schema

    def bind(self, schema: Schema, table_prefix: str) -> None:
        models = {name: model for name, model in schema.items()}
        for name, model in models.items():
            _validate_model(name, model, models)
        referrers: dict[str, list[_Referrer]] = {name: [] for name in models}
        for name, model in models.items():
            for field_name, spec in model.fields.items():
                ref = spec.references
                if ref is not None and ref.model in models:
                    referrers[ref.model].append(_Referrer(name, field_name, ref))
        self.schema = models
        self.referrers = referrers
        self.table_prefix = table_prefix
        tables: dict[str, dict[str, Row]] = {}
        for name, model in models.items():
            # Keep the rows of models that remain, shaped to their new fields.
            tables[name] = {
                row_id: _reshape(model, row)
                for row_id, row in self.tables.get(name, {}).items()
            }
        self.tables = tables

    def model(self, name: str) -> ModelSchema:
        model = self.schema.get(name)
        if model is None:
            hint = "" if self.schema else " (bind_schema() has not been called)"
            msg = f"unknown model {name!r}{hint}"
            raise ValueError(msg)
        return model

    def snapshot(self) -> dict[str, dict[str, Row]]:
        return {name: dict(rows) for name, rows in self.tables.items()}

    def restore(self, snapshot: dict[str, dict[str, Row]]) -> None:
        self.tables = snapshot

    # --------------------------------------------------------------- operations

    def create(self, model_name: str, data: Mapping[str, Any]) -> Row:
        model = self.model(model_name)
        row: Row = {}
        if "id" not in data:
            msg = f"{model_name}: ids are supplied by the caller (ctx.ids)"
            raise ValueError(msg)
        for key, value in data.items():
            row[key] = _normalize(model_name, key, _field(model, key), value)
        if not row["id"]:
            msg = f"{model_name}.id must be a non-empty string"
            raise ValueError(msg)
        for name, spec in model.fields.items():
            if name not in row:
                default = default_value(spec) if spec.default is not None else None
                row[name] = _normalize(model_name, name, spec, default)
        _check_required(model_name, model, row)
        self._check_unique(model_name, model, [row], replaced=set())
        self._check_outgoing(model_name, model, row, row.keys())
        self.tables[model_name][row["id"]] = row
        return copy.deepcopy(row)

    def find(self, model_name: str, where: Sequence[Where]) -> list[Row]:
        model = self.model(model_name)
        matches = _compile(model_name, model, where)
        return [row for row in self.tables[model_name].values() if matches(row)]

    def find_many(
        self,
        model_name: str,
        where: Sequence[Where],
        limit: int | None,
        offset: int | None,
        sort_by: SortBy | None,
    ) -> list[Row]:
        rows = self.find(model_name, where)
        if sort_by is not None:
            rows = _sorted(model_name, self.model(model_name), rows, sort_by)
        if offset is not None:
            if offset < 0:
                msg = "offset must be >= 0"
                raise ValueError(msg)
            rows = rows[offset:]
        if limit is not None:
            if limit < 0:
                msg = "limit must be >= 0"
                raise ValueError(msg)
            rows = rows[:limit]
        return [copy.deepcopy(row) for row in rows]

    def update(
        self,
        model_name: str,
        where: Sequence[Where],
        data: Mapping[str, Any],
        *,
        many: bool,
    ) -> list[Row]:
        model = self.model(model_name)
        changes: Row = {}
        for key, value in data.items():
            if key == "id":
                msg = f"{model_name}.id cannot be changed"
                raise ValueError(msg)
            changes[key] = _normalize(model_name, key, _field(model, key), value)
        matched = self.find(model_name, where)
        if not many:
            matched = matched[:1]
        if not matched:
            return []
        updated = [{**row, **changes} for row in matched]
        for row in updated:
            _check_required(model_name, model, row)
        self._check_unique(
            model_name, model, updated, replaced={row["id"] for row in matched}
        )
        for row in updated:
            self._check_outgoing(model_name, model, row, changes.keys())
        self._check_incoming(model_name, matched, changes)
        table = self.tables[model_name]
        for row in updated:
            table[row["id"]] = row
        return [copy.deepcopy(row) for row in updated]

    def delete(self, model_name: str, where: Sequence[Where]) -> int:
        matched = self.find(model_name, where)
        doomed: dict[str, set[str]] = {name: set() for name in self.tables}
        doomed[model_name].update(row["id"] for row in matched)
        nulls: dict[tuple[str, str], set[str]] = {}
        restricted: list[tuple[str, str, str]] = []
        queue: list[tuple[str, Row]] = [(model_name, row) for row in matched]
        while queue:
            target_model, target = queue.pop()
            for ref in self.referrers.get(target_model, ()):
                value = target.get(ref.reference.field)
                if value is None:
                    continue
                for row_id, row in self.tables[ref.model].items():
                    if row.get(ref.field) != value or row_id in doomed[ref.model]:
                        continue
                    action = ref.reference.on_delete
                    if action == "cascade":
                        doomed[ref.model].add(row_id)
                        queue.append((ref.model, row))
                    elif action == "set_null":
                        nulls.setdefault((ref.model, row_id), set()).add(ref.field)
                    else:
                        restricted.append((ref.model, ref.field, row_id))
        for ref_model, ref_field, row_id in restricted:
            if row_id not in doomed[ref_model]:
                raise ReferenceViolation(ref_model, (ref_field,))
        for (ref_model, row_id), fields in nulls.items():
            if row_id in doomed[ref_model]:
                continue
            table = self.tables[ref_model]
            table[row_id] = {**table[row_id], **dict.fromkeys(fields)}
        for name, ids in doomed.items():
            table = self.tables[name]
            for row_id in ids:
                del table[row_id]
        return len(matched)

    def dump(self) -> dict[str, list[Row]]:
        return {
            name: [copy.deepcopy(row) for row in rows.values()]
            for name, rows in self.tables.items()
        }

    # --------------------------------------------------------------- constraints

    def _check_unique(
        self,
        model_name: str,
        model: ModelSchema,
        candidates: list[Row],
        replaced: set[str],
    ) -> None:
        groups: list[tuple[str, ...]] = [("id",)]
        groups.extend((name,) for name, spec in model.fields.items() if spec.unique)
        groups.extend(tuple(group) for group in model.unique_together)
        others = [
            row
            for row_id, row in self.tables[model_name].items()
            if row_id not in replaced
        ]
        for group in groups:
            seen: set[tuple[object, ...]] = set()
            for row in others:
                key = tuple(_freeze(row.get(name)) for name in group)
                if None not in key:
                    seen.add(key)
            for row in candidates:
                key = tuple(_freeze(row.get(name)) for name in group)
                if None in key:
                    # NULLs never collide, as in SQL.
                    continue
                if key in seen:
                    raise UniqueViolation(model_name, group)
                seen.add(key)

    def _check_outgoing(
        self, model_name: str, model: ModelSchema, row: Row, fields: Iterable[str]
    ) -> None:
        for name in fields:
            spec = model.fields.get(name)
            if spec is None or spec.references is None:
                continue
            ref = spec.references
            value = row.get(name)
            if value is None or ref.model not in self.tables:
                # References to models outside the bound schema are not enforced.
                continue
            target = self.tables[ref.model]
            if ref.field == "id":
                found = value in target
            else:
                found = any(other.get(ref.field) == value for other in target.values())
            if not found:
                raise ReferenceViolation(model_name, (name,))

    def _check_incoming(
        self, model_name: str, matched: list[Row], changes: Row
    ) -> None:
        for ref in self.referrers.get(model_name, ()):
            changed = ref.reference.field
            if changed not in changes:
                continue
            for row in matched:
                old = row.get(changed)
                if old is None or old == changes[changed]:
                    continue
                if any(
                    other.get(ref.field) == old
                    for other in self.tables[ref.model].values()
                ):
                    raise ReferenceViolation(ref.model, (ref.field,))


def _validate_model(
    name: str, model: ModelSchema, models: Mapping[str, ModelSchema]
) -> None:
    if model.name != name:
        msg = f"model registered as {name!r} is named {model.name!r}"
        raise ConfigError(msg)
    for field_name, spec in model.fields.items():
        ref = spec.references
        if ref is None:
            continue
        if ref.on_delete == "set_null" and spec.required:
            msg = f"{name}.{field_name}: on_delete='set_null' needs required=False"
            raise ConfigError(msg)
        target = models.get(ref.model)
        if target is not None and ref.field != "id" and ref.field not in target.fields:
            msg = (
                f"{name}.{field_name} references unknown field {ref.model}.{ref.field}"
            )
            raise ConfigError(msg)
    for group in model.unique_together:
        for field_name in group:
            if field_name != "id" and field_name not in model.fields:
                msg = f"{name}: unique_together names unknown field {field_name!r}"
                raise ConfigError(msg)


def _reshape(model: ModelSchema, row: Row) -> Row:
    shaped: Row = {"id": row["id"]}
    for name, spec in model.fields.items():
        if name in row:
            shaped[name] = row[name]
        else:
            shaped[name] = default_value(spec) if spec.default is not None else None
    return shaped


def _field(model: ModelSchema, name: str) -> Field:
    if name == "id":
        return _ID_FIELD
    spec = model.fields.get(name)
    if spec is None:
        msg = f"unknown field {model.name}.{name}"
        raise ValueError(msg)
    return spec


def _check_required(model_name: str, model: ModelSchema, row: Row) -> None:
    for name, spec in model.fields.items():
        if spec.required and row.get(name) is None:
            msg = f"{model_name}.{name} is required"
            raise ValueError(msg)


def _normalize(
    model_name: str, name: str, spec: Field, value: object, *, query: bool = False
) -> Any:
    """Check a written value against its field type and return the stored form.

    Messages name the field only: values may be secrets such as token hashes.
    """
    if value is None:
        return None
    where = f"{model_name}.{name}"
    kind = spec.type
    if kind in _TEXT:
        if not isinstance(value, str):
            msg = f"{where} expects a string"
            raise ValueError(msg)
        if not query and spec.max_length is not None and len(value) > spec.max_length:
            msg = f"{where} is longer than {spec.max_length} characters"
            raise ValueError(msg)
        return value
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            msg = f"{where} expects an integer"
            raise ValueError(msg)
        return value
    if kind == "boolean":
        if not isinstance(value, bool):
            msg = f"{where} expects a boolean"
            raise ValueError(msg)
        return value
    if kind == "datetime":
        return _aware_utc(where, value)
    if kind == "json":
        # A JSON round trip gives the same values back as a SQL JSON column would.
        try:
            return json.loads(json.dumps(value, allow_nan=False))
        except (TypeError, ValueError) as exc:
            msg = f"{where} expects a JSON-serializable value"
            raise ValueError(msg) from exc
    return _string_list(where, value)


def _aware_utc(where: str, value: object) -> datetime:
    if not isinstance(value, datetime):
        msg = f"{where} expects a datetime"
        raise ValueError(msg)
    if value.tzinfo is None or value.utcoffset() is None:
        msg = f"{where} expects a timezone-aware datetime"
        raise ValueError(msg)
    return value.astimezone(UTC)


def _string_list(where: str, value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        msg = f"{where} expects a list of strings"
        raise ValueError(msg)
    items = list(cast("Iterable[object]", value))
    result: list[str] = []
    for item in items:
        if not isinstance(item, str):
            msg = f"{where} expects a list of strings"
            raise ValueError(msg)
        result.append(item)
    return result


def _freeze(value: object) -> object:
    if isinstance(value, list | dict):
        return json.dumps(value, sort_keys=True)
    return value


def _compile(
    model_name: str, model: ModelSchema, where: Sequence[Where]
) -> Callable[[Row], bool]:
    """Turn ``where`` into a predicate: OR of AND groups, so ``and`` binds tighter."""
    groups: list[list[Callable[[Row], bool]]] = [[]]
    for index, clause in enumerate(where):
        if clause.connector not in ("and", "or"):
            msg = f"invalid connector {clause.connector!r}"
            raise ValueError(msg)
        if index > 0 and clause.connector == "or":
            groups.append([])
        groups[-1].append(_clause(model_name, model, clause))
    if not where:
        return lambda _row: True
    return lambda row: any(all(test(row) for test in group) for group in groups)


def _clause(
    model_name: str, model: ModelSchema, clause: Where
) -> Callable[[Row], bool]:
    name = clause.field
    spec = _field(model, name)
    op = clause.op
    kind = spec.type
    where = f"{model_name}.{name}"
    if op not in _OPS:
        msg = f"invalid operator {op!r}"
        raise ValueError(msg)
    if op == "is_null":
        if not isinstance(clause.value, bool):
            msg = f"is_null on {where} takes True or False"
            raise ValueError(msg)
        want_null = clause.value
        return lambda row: (row.get(name) is None) == want_null
    if op in ("eq", "ne") and clause.value is None:
        if op == "eq":
            return lambda row: row.get(name) is None
        return lambda row: row.get(name) is not None
    if op in ("eq", "ne"):
        _require(kind in _SCALAR, op, where)
        value = _comparable(model_name, name, spec, clause.value)
        if op == "eq":
            return lambda row: row.get(name) == value
        # NULL rows match "ne": None differs from any value.
        return lambda row: row.get(name) != value
    if op in ("lt", "lte", "gt", "gte"):
        _require(kind in _ORDERED, op, where)
        bound = _comparable(model_name, name, spec, clause.value)
        return _ordered(name, op, bound)
    if op in ("in", "not_in"):
        _require(kind in _SCALAR, op, where)
        options = _options(model_name, name, spec, clause.value)
        if op == "in":
            return lambda row: row.get(name) in options
        return lambda row: row.get(name) not in options
    text = clause.value
    if not isinstance(text, str):
        msg = f"{op} on {where} takes a string"
        raise ValueError(msg)
    if op == "contains":
        if kind == "string_list":
            return lambda row: text in (row.get(name) or ())
        _require(kind in _TEXT, op, where)
        return lambda row: isinstance(row.get(name), str) and text in row[name]
    _require(kind in _TEXT, op, where)
    if op == "starts_with":
        return lambda row: isinstance(row.get(name), str) and row[name].startswith(text)
    return lambda row: isinstance(row.get(name), str) and row[name].endswith(text)


def _require(supported: bool, op: str, where: str) -> None:
    if not supported:
        msg = f"operator {op!r} is not supported on {where}"
        raise ValueError(msg)


def _comparable(model_name: str, name: str, spec: Field, value: object) -> object:
    if value is None:
        msg = f"comparison on {model_name}.{name} needs a value; use is_null"
        raise ValueError(msg)
    return _normalize(model_name, name, spec, value, query=True)


def _options(model_name: str, name: str, spec: Field, value: object) -> list[object]:
    if isinstance(value, str | bytes | dict) or not isinstance(
        value, list | tuple | set | frozenset
    ):
        msg = f"in / not_in on {model_name}.{name} takes a list"
        raise ValueError(msg)
    items = list(cast("Iterable[object]", value))
    return [
        None if item is None else _normalize(model_name, name, spec, item, query=True)
        for item in items
    ]


def _ordered(name: str, op: str, bound: Any) -> Callable[[Row], bool]:
    def test(row: Row) -> bool:
        current = row.get(name)
        if current is None:
            return False
        if op == "lt":
            return bool(current < bound)
        if op == "lte":
            return bool(current <= bound)
        if op == "gt":
            return bool(current > bound)
        return bool(current >= bound)

    return test


def _sorted(
    model_name: str, model: ModelSchema, rows: list[Row], sort_by: SortBy
) -> list[Row]:
    name = sort_by.field
    spec = _field(model, name)
    if spec.type not in _SCALAR:
        msg = f"cannot sort by {model_name}.{name}"
        raise ValueError(msg)
    if sort_by.direction not in ("asc", "desc"):
        msg = f"invalid sort direction {sort_by.direction!r}"
        raise ValueError(msg)

    def key(row: Row) -> tuple[bool, Any]:
        value = row.get(name)
        return (value is not None, value if value is not None else 0)

    # NULLs sort first ascending and last descending.
    return sorted(rows, key=key, reverse=sort_by.direction == "desc")


class MemoryAdapter:
    """An :class:`~gotauth.contracts.Adapter` that keeps rows in memory.

    Rows are copied in and out. Every operation and every transaction holds one
    ``asyncio.Lock``, so transactions are serialized and a root operation waits for an
    open transaction to finish.

    Calling the root adapter from the task that holds a transaction raises
    ``RuntimeError`` instead of deadlocking: inside a transaction, use the adapter that
    ``transaction()`` yields. A child task that the transaction awaits and that uses the
    root adapter still deadlocks; give it the transaction adapter.
    """

    id: str = "memory"

    def __init__(self) -> None:
        self._store = _Store()
        self._lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None
        self._active: _MemoryTransaction | None = None

    @property
    def table_prefix(self) -> str:
        """The ``table_prefix`` given to :meth:`bind_schema`."""
        return self._store.table_prefix

    def table_name(self, model: str) -> str:
        """Return the table name a SQL adapter would use for ``model``."""
        return table_name(self._store.model(model), self._store.table_prefix)

    def bind_schema(self, schema: Schema, *, table_prefix: str = "auth_") -> None:
        """Bind the merged schema. Rebinding keeps the rows of models that remain."""
        if self._active is not None:
            msg = "cannot bind a schema during a transaction"
            raise RuntimeError(msg)
        self._store.bind(schema, table_prefix)

    def dump(self) -> dict[str, list[dict[str, Any]]]:
        """Return a copy of every row by model, e.g. to check no raw token is stored."""
        return self._store.dump()

    async def create(self, model: str, data: Mapping[str, Any]) -> dict[str, Any]:
        """Insert a row and return a copy of it."""
        return await self._locked(lambda: self._store.create(model, data))

    async def find_one(
        self, model: str, where: Sequence[Where]
    ) -> dict[str, Any] | None:
        """Return a copy of the first matching row, or ``None``."""
        rows = await self._locked(
            lambda: self._store.find_many(model, where, 1, None, None)
        )
        return rows[0] if rows else None

    async def find_many(
        self,
        model: str,
        where: Sequence[Where] = (),
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort_by: SortBy | None = None,
    ) -> list[dict[str, Any]]:
        """Return copies of the matching rows."""
        return await self._locked(
            lambda: self._store.find_many(model, where, limit, offset, sort_by)
        )

    async def count(self, model: str, where: Sequence[Where] = ()) -> int:
        """Return the number of matching rows."""
        return await self._locked(lambda: len(self._store.find(model, where)))

    async def update(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        """Update the first matching row (compare-and-set); return it or ``None``."""
        rows = await self._locked(
            lambda: self._store.update(model, where, data, many=False)
        )
        return rows[0] if rows else None

    async def update_many(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> int:
        """Update every matching row; return the count."""
        rows = await self._locked(
            lambda: self._store.update(model, where, data, many=True)
        )
        return len(rows)

    async def delete(self, model: str, where: Sequence[Where]) -> int:
        """Delete the matching rows, applying ``on_delete``; return the count."""
        return await self._locked(lambda: self._store.delete(model, where))

    def transaction(self) -> AbstractAsyncContextManager[Adapter]:
        """Open a transaction: a snapshot that is restored if the block raises."""
        return self._transaction()

    @asynccontextmanager
    async def _transaction(self) -> AsyncGenerator[Adapter, None]:
        self._check_owner()
        async with self._get_lock():
            snapshot = self._store.snapshot()
            transaction = _MemoryTransaction(self._store, asyncio.current_task())
            self._active = transaction
            try:
                yield transaction
            except BaseException:
                self._store.restore(snapshot)
                raise
            finally:
                transaction.closed = True
                self._active = None

    async def _locked(self, operation: Callable[[], T]) -> T:
        self._check_owner()
        async with self._get_lock():
            return operation()

    def _check_owner(self) -> None:
        active = self._active
        if active is not None and active.owner is asyncio.current_task():
            msg = (
                "the root memory adapter was used inside its own open transaction; "
                "use the adapter yielded by transaction()"
            )
            raise RuntimeError(msg)

    def _get_lock(self) -> asyncio.Lock:
        # asyncio.Lock belongs to one event loop; tests often run one loop per test.
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            if self._active is not None:
                msg = "memory adapter used from another event loop during a transaction"
                raise RuntimeError(msg)
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock


class _MemoryTransaction:
    """The adapter a memory transaction yields; nested ``transaction()`` reuses it."""

    id: str = "memory"

    def __init__(self, store: _Store, owner: asyncio.Task[Any] | None) -> None:
        self._store = store
        self.owner = owner
        self.closed = False

    def bind_schema(self, schema: Schema, *, table_prefix: str = "auth_") -> None:
        """Not allowed inside a transaction; bind the root adapter."""
        msg = "bind_schema() must be called on the root adapter"
        raise RuntimeError(msg)

    def _open(self) -> _Store:
        if self.closed:
            msg = "this memory transaction has already ended"
            raise RuntimeError(msg)
        return self._store

    async def create(self, model: str, data: Mapping[str, Any]) -> dict[str, Any]:
        """Insert a row inside the transaction."""
        return self._open().create(model, data)

    async def find_one(
        self, model: str, where: Sequence[Where]
    ) -> dict[str, Any] | None:
        """Return the first matching row, or ``None``."""
        rows = self._open().find_many(model, where, 1, None, None)
        return rows[0] if rows else None

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
        return self._open().find_many(model, where, limit, offset, sort_by)

    async def count(self, model: str, where: Sequence[Where] = ()) -> int:
        """Return the number of matching rows."""
        return len(self._open().find(model, where))

    async def update(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        """Update the first matching row; return it or ``None``."""
        rows = self._open().update(model, where, data, many=False)
        return rows[0] if rows else None

    async def update_many(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> int:
        """Update every matching row; return the count."""
        return len(self._open().update(model, where, data, many=True))

    async def delete(self, model: str, where: Sequence[Where]) -> int:
        """Delete the matching rows; return the count."""
        return self._open().delete(model, where)

    def transaction(self) -> AbstractAsyncContextManager[Adapter]:
        """Reuse this transaction (no savepoint)."""
        return self._reuse()

    @asynccontextmanager
    async def _reuse(self) -> AsyncGenerator[Adapter, None]:
        self._open()
        yield self


def memory_adapter() -> MemoryAdapter:
    """Return a new, empty :class:`MemoryAdapter`. ``GotAuth(...)`` binds its schema."""
    return MemoryAdapter()
