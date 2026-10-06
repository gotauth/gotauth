"""Secondary storage: memory with a fake clock, Redis on the compose service."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest

from gotauth.contracts import SecondaryStorage
from gotauth.sessions import memory_secondary_storage, redis_secondary_storage
from gotauth.testing import fake_clock


async def test_memory_storage_honours_ttl() -> None:
    clock = fake_clock()
    storage = memory_secondary_storage(clock=clock)
    assert isinstance(storage, SecondaryStorage)
    await storage.set("a", "1", 10)
    await storage.set("b", "2")
    clock.advance(9)
    assert await storage.get("a") == "1"
    clock.advance(1)
    assert await storage.get("a") is None
    assert await storage.get("b") == "2"
    await storage.delete("b")
    assert await storage.get("b") is None


async def test_memory_incr_sets_the_ttl_once() -> None:
    clock = fake_clock()
    storage = memory_secondary_storage(clock=clock)
    assert await storage.incr("n", 10) == 1
    clock.advance(6)
    assert await storage.incr("n", 10) == 2  # does not push the expiry out
    clock.advance(4)
    assert await storage.incr("n", 10) == 1


async def test_memory_incr_is_atomic_under_gather() -> None:
    storage = memory_secondary_storage()
    results = await asyncio.gather(*(storage.incr("n", 60) for _ in range(50)))
    assert sorted(results) == list(range(1, 51))


def test_redis_needs_url_or_client() -> None:
    with pytest.raises(ValueError, match="url or client"):
        redis_secondary_storage()


@pytest.mark.redis
async def test_redis_storage() -> None:
    prefix = f"gotauth-test-{uuid.uuid4().hex}:"
    storage = redis_secondary_storage(
        os.environ["GOTAUTH_TEST_REDIS_URL"], key_prefix=prefix
    )
    await storage.set("a", "1", 30)
    assert await storage.get("a") == "1"
    await storage.delete("a")
    assert await storage.get("a") is None
    results = await asyncio.gather(*(storage.incr("n", 30) for _ in range(50)))
    assert sorted(results) == list(range(1, 51))
    client = storage._client  # type: ignore[attr-defined]
    ttl = await client.ttl(prefix + "n")
    assert 0 < ttl <= 30
    await client.expire(prefix + "n", 1000)
    await storage.incr("n", 30)
    # The TTL is set only on the first increment.
    assert await client.ttl(prefix + "n") > 30
    await client.delete(prefix + "n")
    await client.aclose()
