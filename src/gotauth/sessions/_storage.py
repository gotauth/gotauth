"""Secondary storage backends (CONTRACTS 7): memory and Redis."""

from __future__ import annotations

import asyncio
import importlib
from datetime import datetime, timedelta
from typing import Any, cast

from gotauth.contracts.primitives import Clock, SystemClock
from gotauth.contracts.sessions import SecondaryStorage

__all__ = [
    "MemorySecondaryStorage",
    "RedisSecondaryStorage",
    "memory_secondary_storage",
    "redis_secondary_storage",
]


class MemorySecondaryStorage:
    """A ``SecondaryStorage`` in process memory, for tests and single-process apps."""

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock: Clock = clock or SystemClock()
        self._values: dict[str, tuple[str, datetime | None]] = {}
        self._lock = asyncio.Lock()

    def _live(self, key: str) -> str | None:
        found = self._values.get(key)
        if found is None:
            return None
        value, expires = found
        if expires is not None and self._clock.now() >= expires:
            del self._values[key]
            return None
        return value

    async def get(self, key: str) -> str | None:
        """Return the value, or ``None`` when missing or expired."""
        return self._live(key)

    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        """Store a value, with an optional time to live."""
        expires = (
            self._clock.now() + timedelta(seconds=ttl_seconds) if ttl_seconds else None
        )
        self._values[key] = (value, expires)

    async def delete(self, key: str) -> None:
        """Remove a value."""
        self._values.pop(key, None)

    async def incr(self, key: str, ttl_seconds: int) -> int:
        """Add one; the TTL is set only by the first increment."""
        async with self._lock:
            current = self._live(key)
            if current is None:
                await self.set(key, "1", ttl_seconds)
                return 1
            value, expires = self._values[key]
            count = int(value) + 1
            self._values[key] = (str(count), expires)
            return count


_INCR = """
local value = redis.call('INCR', KEYS[1])
if value == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return value
"""


class RedisSecondaryStorage:
    """A ``SecondaryStorage`` on Redis (the ``redis`` extra)."""

    def __init__(
        self, client: Any, *, key_prefix: str = "gotauth:"
    ) -> None:  # Any: redis client
        self._client = client
        self._prefix = key_prefix
        self._incr = client.register_script(_INCR)

    async def get(self, key: str) -> str | None:
        """Return the value, or ``None``."""
        value = await self._client.get(self._prefix + key)
        if value is None:
            return None
        return value.decode() if isinstance(value, bytes) else str(value)

    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        """Store a value, with an optional time to live."""
        await self._client.set(self._prefix + key, value, ex=ttl_seconds or None)

    async def delete(self, key: str) -> None:
        """Remove a value."""
        await self._client.delete(self._prefix + key)

    async def incr(self, key: str, ttl_seconds: int) -> int:
        """Add one atomically; the TTL is set only by the first increment (Lua)."""
        return int(await self._incr(keys=[self._prefix + key], args=[ttl_seconds]))


def memory_secondary_storage(*, clock: Clock | None = None) -> MemorySecondaryStorage:
    """Return an in-memory secondary storage."""
    return MemorySecondaryStorage(clock=clock)


def redis_secondary_storage(
    url: str | None = None,
    *,
    client: Any = None,
    key_prefix: str = "gotauth:",  # Any: redis client
) -> SecondaryStorage:
    """Return a Redis secondary storage from a URL or a ``redis.asyncio`` client.

    Raises:
        ValueError: When neither ``url`` nor ``client`` is given.
    """
    if client is None:
        if url is None:
            raise ValueError("give url or client")
        redis_asyncio = importlib.import_module("redis.asyncio")  # the redis extra
        client = redis_asyncio.from_url(url)
    return cast(
        "SecondaryStorage", RedisSecondaryStorage(client, key_prefix=key_prefix)
    )
