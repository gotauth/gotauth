"""The memory adapter against the shared conformance suite, plus its own rules."""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gotauth.contracts import Adapter, SortBy, Where
from gotauth.storage.memory import MemoryAdapter, memory_adapter
from gotauth.testing import CONFORMANCE_SCHEMA, adapter_conformance


async def _make() -> Adapter:
    return memory_adapter()


class TestMemoryConformance(adapter_conformance(_make)):  # type: ignore[misc]
    """Every section 3 rule."""


def _bound() -> MemoryAdapter:
    made = memory_adapter()
    made.bind_schema(CONFORMANCE_SCHEMA, table_prefix="conf_")
    return made


def test_table_names_use_the_prefix() -> None:
    assert _bound().table_name("owner") == "conf_owner"


async def test_root_adapter_inside_its_own_transaction_raises() -> None:
    made = _bound()
    async with made.transaction():
        with pytest.raises(RuntimeError):
            await made.count("owner")


async def test_transactions_are_serialized() -> None:
    made = _bound()
    await made.create("owner", {"id": "o1", "name": "ada", "age": 0})

    async def bump() -> None:
        async with made.transaction() as tx:
            row = await tx.find_one("owner", [Where("id", "o1")])
            assert row is not None
            await asyncio.sleep(0)
            await tx.update("owner", [Where("id", "o1")], {"age": row["age"] + 1})

    await asyncio.gather(*(bump() for _ in range(20)))
    row = await made.find_one("owner", [Where("id", "o1")])
    assert row is not None
    assert row["age"] == 20


names = st.text(alphabet="abcdefghij", min_size=1, max_size=6)


@settings(max_examples=40, deadline=None)
@given(
    initial=st.lists(names, unique=True, min_size=1, max_size=6),
    added=st.lists(names, unique=True, max_size=4),
)
def test_rollback_restores_the_exact_prior_state(
    initial: list[str], added: list[str]
) -> None:
    async def run() -> None:
        made = _bound()
        for index, name in enumerate(initial):
            await made.create("owner", {"id": f"o{index}", "name": name, "age": index})
        before = await made.find_many("owner", sort_by=SortBy("id"))

        class Boom(Exception):
            pass

        with pytest.raises(Boom):
            async with made.transaction() as tx:
                for index, name in enumerate(added):
                    if name not in initial:
                        await tx.create("owner", {"id": f"n{index}", "name": name})
                await tx.update_many("owner", [], {"age": 99})
                await tx.delete("owner", [Where("id", "o0")])
                raise Boom
        assert await made.find_many("owner", sort_by=SortBy("id")) == before

    asyncio.run(run())


@settings(max_examples=25, deadline=None)
@given(attempts=st.integers(min_value=2, max_value=20))
def test_parallel_compare_and_set_wins_exactly_once(attempts: int) -> None:
    async def run() -> None:
        made = _bound()
        await made.create("owner", {"id": "o1", "name": "ada"})
        await made.create("lock", {"id": "l1", "owner_id": "o1", "version": 1})
        results = await asyncio.gather(
            *(
                made.update(
                    "lock", [Where("id", "l1"), Where("version", 1)], {"version": 2}
                )
                for _ in range(attempts)
            )
        )
        assert sum(result is not None for result in results) == 1

    asyncio.run(run())
