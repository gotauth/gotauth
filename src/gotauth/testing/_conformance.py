"""Adapter conformance suite (CONTRACTS sections 3 and 15).

This module is test code shipped in the package, so it uses ``assert``.

``adapter_conformance(factory)`` returns a pytest test class. Subclass it in an
adapter's tests::

    from gotauth.testing import adapter_conformance, memory_adapter

    async def make() -> Adapter:
        return memory_adapter()

    class TestMemoryAdapter(adapter_conformance(make)):
        pass

pytest and hypothesis are imported inside the function, so ``gotauth.testing`` keeps
importing with the core dependencies only (CI no-extras job).
"""

# ruff: noqa: S101
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from gotauth.contracts.adapter import Adapter, SortBy, Where
from gotauth.contracts.errors import ReferenceViolation, UniqueViolation
from gotauth.contracts.schema import Field, ModelSchema, Reference, Schema

__all__ = ["CONFORMANCE_SCHEMA", "adapter_conformance"]

AdapterFactory = Callable[[], Awaitable[Adapter]]

# A schema that uses every FieldType, a unique_together group and each on_delete mode.
CONFORMANCE_SCHEMA: Schema = {
    "owner": ModelSchema(
        name="owner",
        fields={
            "name": Field(type="string", unique=True, max_length=100),
            "bio": Field(type="text", required=False),
            "age": Field(type="integer", required=False),
            "active": Field(type="boolean", default=True),
            "joined_at": Field(type="datetime", required=False),
            "settings": Field(type="json", required=False),
            "tags": Field(type="string_list", required=False),
            "nickname": Field(type="string", required=False, unique=True),
        },
    ),
    "pet": ModelSchema(
        name="pet",
        fields={
            "owner_id": Field(type="string", references=Reference(model="owner")),
            "kind": Field(type="string"),
            "label": Field(type="string"),
        },
        unique_together=(("owner_id", "label"),),
    ),
    "note": ModelSchema(
        name="note",
        fields={
            "owner_id": Field(
                type="string",
                required=False,
                references=Reference(model="owner", on_delete="set_null"),
            ),
            "body": Field(type="text"),
        },
    ),
    "lock": ModelSchema(
        name="lock",
        fields={
            "owner_id": Field(
                type="string", references=Reference(model="owner", on_delete="restrict")
            ),
            "version": Field(type="integer"),
        },
    ),
}

_T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _owner(row_id: str, name: str, **extra: Any) -> dict[str, Any]:  # Any: field values
    return {"id": row_id, "name": name, **extra}


def adapter_conformance(factory: AdapterFactory) -> type:
    """Return a pytest class that checks an adapter against every section 3 rule.

    Args:
        factory: Returns a new, empty adapter. The suite binds ``CONFORMANCE_SCHEMA``
            with ``table_prefix="conf_"``.

    Returns:
        A test class to subclass (pytest collects classes named ``Test*``).
    """
    import pytest  # dev-only; imported lazily on purpose

    class AdapterConformance:
        """Section 3 rules every adapter follows."""

        @pytest.fixture
        async def adapter(self) -> Adapter:
            made = await factory()
            made.bind_schema(CONFORMANCE_SCHEMA, table_prefix="conf_")
            return made

        # -------------------------------------------------------------- round trips

        async def test_create_returns_the_stored_row(self, adapter: Adapter) -> None:
            row = await adapter.create("owner", _owner("o1", "ada", age=36))
            assert row["id"] == "o1"
            assert row["name"] == "ada"
            assert row["age"] == 36
            assert await adapter.find_one("owner", [Where("id", "o1")]) == row

        async def test_find_one_missing_is_none(self, adapter: Adapter) -> None:
            assert await adapter.find_one("owner", [Where("id", "nope")]) is None

        async def test_every_field_type_round_trips(self, adapter: Adapter) -> None:
            offset = timezone(timedelta(hours=3))
            await adapter.create(
                "owner",
                _owner(
                    "o1",
                    "ada",
                    bio="x" * 5000,
                    age=-7,
                    active=False,
                    joined_at=_T0.astimezone(offset),
                    settings={"a": [1, 2, {"b": None}], "c": "d"},
                    tags=["x", "y"],
                ),
            )
            row = await adapter.find_one("owner", [Where("id", "o1")])
            assert row is not None
            assert row["bio"] == "x" * 5000
            assert row["age"] == -7
            assert row["active"] is False
            assert row["joined_at"] == _T0
            assert row["joined_at"].utcoffset() == timedelta(0)
            assert row["settings"] == {"a": [1, 2, {"b": None}], "c": "d"}
            assert row["tags"] == ["x", "y"]

        async def test_returned_rows_are_copies(self, adapter: Adapter) -> None:
            row = await adapter.create("owner", _owner("o1", "ada", tags=["x"]))
            row["tags"].append("mutated")
            again = await adapter.find_one("owner", [Where("id", "o1")])
            assert again is not None
            assert again["tags"] == ["x"]

        # -------------------------------------------------------------- uniqueness

        async def test_unique_field(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada"))
            with pytest.raises(UniqueViolation):
                await adapter.create("owner", _owner("o2", "ada"))

        async def test_unique_allows_several_nulls(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada", nickname=None))
            await adapter.create("owner", _owner("o2", "bob", nickname=None))
            assert await adapter.count("owner") == 2

        async def test_unique_together(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada"))
            await adapter.create("owner", _owner("o2", "bob"))
            pet = {"kind": "cat", "label": "tom"}
            await adapter.create("pet", {"id": "p1", "owner_id": "o1", **pet})
            await adapter.create("pet", {"id": "p2", "owner_id": "o2", **pet})
            with pytest.raises(UniqueViolation):
                await adapter.create("pet", {"id": "p3", "owner_id": "o1", **pet})

        async def test_update_into_a_unique_clash(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada"))
            await adapter.create("owner", _owner("o2", "bob"))
            with pytest.raises(UniqueViolation):
                await adapter.update("owner", [Where("id", "o2")], {"name": "ada"})

        # -------------------------------------------------------------- where

        async def _seed(self, adapter: Adapter) -> None:
            await adapter.create(
                "owner", _owner("o1", "ada", age=36, bio="likes cats", tags=["a", "b"])
            )
            await adapter.create(
                "owner", _owner("o2", "bob", age=20, bio="likes dogs", tags=["b"])
            )
            await adapter.create(
                "owner", _owner("o3", "cy", age=None, bio=None, tags=[])
            )

        async def _ids(self, adapter: Adapter, where: list[Where]) -> list[str]:
            rows = await adapter.find_many("owner", where, sort_by=SortBy("id"))
            return [row["id"] for row in rows]

        async def test_comparison_operators(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            assert await self._ids(adapter, [Where("age", 20)]) == ["o2"]
            assert await self._ids(adapter, [Where("name", "ada", "ne")]) == [
                "o2",
                "o3",
            ]
            assert await self._ids(adapter, [Where("age", 36, "lt")]) == ["o2"]
            assert await self._ids(adapter, [Where("age", 36, "lte")]) == ["o1", "o2"]
            assert await self._ids(adapter, [Where("age", 20, "gt")]) == ["o1"]
            assert await self._ids(adapter, [Where("age", 20, "gte")]) == ["o1", "o2"]

        async def test_in_and_not_in(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            assert await self._ids(adapter, [Where("name", ["ada", "cy"], "in")]) == [
                "o1",
                "o3",
            ]
            assert await self._ids(adapter, [Where("name", ["ada"], "not_in")]) == [
                "o2",
                "o3",
            ]
            assert await self._ids(adapter, [Where("name", [], "in")]) == []

        async def test_string_operators(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            assert await self._ids(adapter, [Where("bio", "cat", "contains")]) == ["o1"]
            assert await self._ids(adapter, [Where("bio", "likes", "starts_with")]) == [
                "o1",
                "o2",
            ]
            assert await self._ids(adapter, [Where("bio", "dogs", "ends_with")]) == [
                "o2"
            ]

        async def test_like_wildcards_are_literal(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            assert await self._ids(adapter, [Where("bio", "%", "contains")]) == []
            assert (
                await self._ids(adapter, [Where("bio", "l_kes", "starts_with")]) == []
            )

        async def test_contains_on_string_list_is_membership(
            self, adapter: Adapter
        ) -> None:
            await self._seed(adapter)
            assert await self._ids(adapter, [Where("tags", "b", "contains")]) == [
                "o1",
                "o2",
            ]
            assert await self._ids(adapter, [Where("tags", "a", "contains")]) == ["o1"]

        async def test_null_checks(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            assert await self._ids(adapter, [Where("age", True, "is_null")]) == ["o3"]
            assert await self._ids(adapter, [Where("age", False, "is_null")]) == [
                "o1",
                "o2",
            ]
            assert await self._ids(adapter, [Where("age", None)]) == ["o3"]

        async def test_and_binds_tighter_than_or(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            # name = cy OR (age = 36 AND name = bob) -> only o3
            where = [
                Where("name", "cy"),
                Where("age", 36, connector="or"),
                Where("name", "bob"),
            ]
            assert await self._ids(adapter, where) == ["o3"]

        async def test_sort_limit_offset_count(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            rows = await adapter.find_many(
                "owner", sort_by=SortBy("name", "desc"), limit=2, offset=1
            )
            assert [row["name"] for row in rows] == ["bob", "ada"]
            assert await adapter.count("owner") == 3
            assert await adapter.count("owner", [Where("age", 30, "gt")]) == 1

        # -------------------------------------------------------------- writes

        async def test_update_changes_at_most_one_row(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            row = await adapter.update(
                "owner", [Where("bio", "likes", "starts_with")], {"age": 1}
            )
            assert row is not None
            assert row["age"] == 1
            assert await adapter.count("owner", [Where("age", 1)]) == 1

        async def test_update_without_match_is_none(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            assert await adapter.update("owner", [Where("id", "x")], {"age": 1}) is None

        async def test_update_many_and_delete_counts(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            assert (
                await adapter.update_many(
                    "owner", [Where("bio", "likes", "starts_with")], {"active": False}
                )
                == 2
            )
            assert await adapter.delete("owner", [Where("active", False)]) == 2
            assert await adapter.delete("owner", [Where("active", False)]) == 0
            assert await adapter.count("owner") == 1

        async def test_compare_and_set(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada"))
            await adapter.create("lock", {"id": "l1", "owner_id": "o1", "version": 1})
            first = await adapter.update(
                "lock", [Where("id", "l1"), Where("version", 1)], {"version": 2}
            )
            second = await adapter.update(
                "lock", [Where("id", "l1"), Where("version", 1)], {"version": 2}
            )
            assert first is not None
            assert second is None

        async def test_parallel_compare_and_set_wins_once(
            self, adapter: Adapter
        ) -> None:
            await adapter.create("owner", _owner("o1", "ada"))
            await adapter.create("lock", {"id": "l1", "owner_id": "o1", "version": 1})
            results = await asyncio.gather(
                *(
                    adapter.update(
                        "lock", [Where("id", "l1"), Where("version", 1)], {"version": 2}
                    )
                    for _ in range(20)
                )
            )
            assert sum(result is not None for result in results) == 1

        async def test_parallel_single_use_delete_wins_once(
            self, adapter: Adapter
        ) -> None:
            await adapter.create("owner", _owner("o1", "ada"))
            results = await asyncio.gather(
                *(adapter.delete("owner", [Where("id", "o1")]) for _ in range(20))
            )
            assert sorted(results) == [0] * 19 + [1]

        # -------------------------------------------------------------- references

        async def test_reference_must_exist(self, adapter: Adapter) -> None:
            with pytest.raises(ReferenceViolation):
                await adapter.create(
                    "pet",
                    {"id": "p1", "owner_id": "ghost", "kind": "cat", "label": "t"},
                )

        async def test_on_delete_cascade_and_set_null(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada"))
            await adapter.create(
                "pet", {"id": "p1", "owner_id": "o1", "kind": "cat", "label": "t"}
            )
            await adapter.create("note", {"id": "n1", "owner_id": "o1", "body": "hi"})
            assert await adapter.delete("owner", [Where("id", "o1")]) == 1
            assert await adapter.count("pet") == 0
            note = await adapter.find_one("note", [Where("id", "n1")])
            assert note is not None
            assert note["owner_id"] is None

        async def test_on_delete_restrict(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada"))
            await adapter.create("lock", {"id": "l1", "owner_id": "o1", "version": 1})
            with pytest.raises(ReferenceViolation):
                await adapter.delete("owner", [Where("id", "o1")])
            assert await adapter.count("owner") == 1

        # -------------------------------------------------------------- transactions

        async def test_transaction_commits(self, adapter: Adapter) -> None:
            async with adapter.transaction() as tx:
                await tx.create("owner", _owner("o1", "ada"))
            assert await adapter.count("owner") == 1

        async def test_transaction_rolls_back_exactly(self, adapter: Adapter) -> None:
            await self._seed(adapter)
            before = await adapter.find_many("owner", sort_by=SortBy("id"))

            class Boom(Exception):
                pass

            with pytest.raises(Boom):
                async with adapter.transaction() as tx:
                    await tx.create("owner", _owner("o9", "zed"))
                    await tx.update("owner", [Where("id", "o1")], {"age": 99})
                    await tx.delete("owner", [Where("id", "o2")])
                    raise Boom
            assert await adapter.find_many("owner", sort_by=SortBy("id")) == before

        async def test_nested_transaction_reuses_the_outer(
            self, adapter: Adapter
        ) -> None:
            class Boom(Exception):
                pass

            with pytest.raises(Boom):
                async with adapter.transaction() as outer:
                    async with outer.transaction() as inner:
                        await inner.create("owner", _owner("o1", "ada"))
                    raise Boom
            assert await adapter.count("owner") == 0

        async def test_null_rows_in_ne_and_membership(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada", age=36))
            await adapter.create("owner", _owner("o2", "bob", age=20))
            await adapter.create("owner", _owner("o3", "cy"))  # age NULL
            assert await self._ids(adapter, [Where("age", 36, "ne")]) == ["o2", "o3"]
            assert await self._ids(adapter, [Where("age", [36, None], "in")]) == [
                "o1",
                "o3",
            ]
            assert await self._ids(adapter, [Where("age", [36], "not_in")]) == [
                "o2",
                "o3",
            ]
            assert await self._ids(adapter, [Where("age", [36, None], "not_in")]) == [
                "o2"
            ]
            assert await self._ids(adapter, [Where("age", [None], "in")]) == ["o3"]

        async def test_sort_puts_nulls_first_ascending(self, adapter: Adapter) -> None:
            await adapter.create("owner", _owner("o1", "ada", age=36))
            await adapter.create("owner", _owner("o2", "bob"))
            await adapter.create("owner", _owner("o3", "cy", age=20))
            up = await adapter.find_many("owner", sort_by=SortBy("age"))
            down = await adapter.find_many("owner", sort_by=SortBy("age", "desc"))
            assert [row["id"] for row in up] == ["o2", "o3", "o1"]
            assert [row["id"] for row in down] == ["o1", "o3", "o2"]

        async def test_unique_violation_keeps_the_transaction_usable(
            self, adapter: Adapter
        ) -> None:
            # CONTRACTS 3 (CCR 001): callers catch the error and carry on.
            async with adapter.transaction() as tx:
                await tx.create("owner", _owner("o1", "ada"))
                with pytest.raises(UniqueViolation):
                    await tx.create("owner", _owner("o2", "ada"))
                await tx.create("owner", _owner("o3", "bob"))
            assert await adapter.count("owner") == 2

    return AdapterConformance
