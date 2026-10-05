"""Fixed-window rate limiting (CONTRACTS 10.2).

Counting happens outside the request transaction, so a rolled-back request still
counts. Rules come from four places; for one key kind the first source that has a
matching rule wins, in this order: the endpoint's own ``rate_limit``, plugin rules,
config ``rules``, then ``DEFAULT_RATE_LIMITS``. Within a source the most specific path
wins: an exact path, then the longest prefix, then ``"*"``.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from gotauth.contracts.adapter import Adapter, Where
from gotauth.contracts.errors import AuthError, UniqueViolation
from gotauth.contracts.primitives import Clock, IdGenerator, to_timedelta
from gotauth.contracts.protection import (
    DEFAULT_RATE_LIMITS,
    RateLimitKey,
    RateLimitRule,
)
from gotauth.contracts.schema import Field, ModelSchema
from gotauth.contracts.sessions import SecondaryStorage

if TYPE_CHECKING:
    from gotauth.contracts.endpoints import Endpoint
    from gotauth.core._context import RequestContext

__all__ = ["RATE_LIMIT_MODEL", "RateLimiter", "select_rules"]

RATE_LIMIT_MODEL = ModelSchema(
    name="rate_limit",
    fields={
        "key": Field(type="string", unique=True, max_length=255),
        "count": Field(type="integer"),
        "reset_at": Field(type="datetime"),
    },
)
"""Merged into the schema only when ``rate_limit.storage == "database"``."""

EARLY_KEYS: tuple[RateLimitKey, ...] = ("ip", "ip_path")
LATE_KEYS: tuple[RateLimitKey, ...] = ("identifier", "principal")


def _specificity(rule_path: str, path: str) -> int | None:
    """Return how specific a matching rule is (higher wins), or None if no match."""
    if rule_path == path:
        return 1_000_000
    if rule_path == "*":
        return 0
    if rule_path.endswith("*") and path.startswith(rule_path[:-1]):
        return len(rule_path)
    return None


def select_rules(
    path: str, sources: Sequence[Sequence[RateLimitRule]], keys: Sequence[RateLimitKey]
) -> list[RateLimitRule]:
    """Pick at most one rule per key kind for ``path``.

    Args:
        path: The request path relative to the mount.
        sources: Rule lists in precedence order.
        keys: The key kinds to consider.

    Returns:
        The chosen rules.
    """
    chosen: list[RateLimitRule] = []
    for key in keys:
        for rules in sources:
            best: tuple[int, RateLimitRule] | None = None
            for rule in rules:
                if rule.key != key:
                    continue
                score = _specificity(rule.path, path)
                if score is not None and (best is None or score > best[0]):
                    best = (score, rule)
            if best is not None:
                chosen.append(best[1])
                break
    return chosen


@dataclass
class _Window:
    count: int
    reset_at: datetime


class RateLimiter:
    """Counts requests per rule and key, and raises RATE_LIMITED over the limit."""

    def __init__(
        self,
        *,
        enabled: bool,
        storage: str,
        clock: Clock,
        ids: IdGenerator,
        config_rules: Sequence[RateLimitRule],
        plugin_rules: Sequence[RateLimitRule],
        adapter: Adapter,
        secondary: SecondaryStorage | None,
    ) -> None:
        self.enabled = enabled
        self._storage = storage
        self._clock = clock
        self._ids = ids
        self._config_rules = tuple(config_rules)
        self._plugin_rules = tuple(plugin_rules)
        self._adapter = adapter
        self._secondary = secondary
        self._memory: dict[str, _Window] = {}
        self._lock = asyncio.Lock()

    def rules_for(
        self, endpoint: Endpoint[Any, Any], path: str, keys: Sequence[RateLimitKey]
    ) -> list[RateLimitRule]:
        """Return the rules that apply to ``endpoint`` at ``path`` for ``keys``."""
        own = (endpoint.rate_limit,) if endpoint.rate_limit is not None else ()
        sources = (own, self._plugin_rules, self._config_rules, DEFAULT_RATE_LIMITS)
        return select_rules(path, sources, keys)

    async def check(
        self,
        ctx: RequestContext,
        endpoint: Endpoint[Any, Any],
        keys: Sequence[RateLimitKey],
        data: Any = None,  # Any: the validated input model of the endpoint
    ) -> None:
        """Count this request against every applicable rule.

        Raises:
            AuthError: RATE_LIMITED with ``Retry-After`` over any limit.
        """
        if not self.enabled:
            return
        path = ctx.request.path
        for rule in self.rules_for(endpoint, path, keys):
            value = self._key_value(ctx, rule, data)
            if value is None:
                continue
            key = f"{rule.path}|{rule.key}|{value}"
            allowed, retry_after = await self._hit(key, rule)
            if not allowed:
                raise AuthError(
                    "RATE_LIMITED", 429, headers={"retry-after": str(retry_after)}
                )

    def _key_value(
        self, ctx: RequestContext, rule: RateLimitRule, data: Any
    ) -> str | None:
        request = ctx.request
        if rule.key == "ip":
            return request.client_ip or "unknown"
        if rule.key == "ip_path":
            return f"{request.client_ip or 'unknown'}|{request.path}"
        if rule.key == "principal":
            principal = ctx.principal
            return principal.credential_id if principal is not None else None
        identifier = rule.identifier
        if identifier is None:
            return None
        if isinstance(identifier, str):
            raw = getattr(data, identifier, None) if data is not None else None
        else:
            raw = identifier(ctx, data)
        if not isinstance(raw, str) or not raw.strip():
            return None
        # Hashed so a storage dump never shows email addresses.
        return ctx.crypto.hash_token(raw.strip().lower())

    async def _hit(self, key: str, rule: RateLimitRule) -> tuple[bool, int]:
        window = to_timedelta(rule.window)
        if self._storage == "secondary" and self._secondary is not None:
            seconds = max(1, math.ceil(window.total_seconds()))
            count = await self._secondary.incr(f"gotauth:rl:{key}", seconds)
            return count <= rule.max, seconds
        if self._storage == "database":
            return await self._hit_database(key, rule)
        now = self._clock.now()
        async with self._lock:
            current = self._memory.get(key)
            if current is None or now >= current.reset_at:
                current = _Window(count=0, reset_at=now + window)
                self._memory[key] = current
            current.count += 1
            retry = max(1, math.ceil((current.reset_at - now).total_seconds()))
            return current.count <= rule.max, retry

    async def _hit_database(self, key: str, rule: RateLimitRule) -> tuple[bool, int]:
        window = to_timedelta(rule.window)
        hashed = key[:255]
        for _ in range(5):  # compare-and-set retries under contention
            now = self._clock.now()
            row = await self._adapter.find_one("rate_limit", [Where("key", hashed)])
            if row is None:
                try:
                    await self._adapter.create(
                        "rate_limit",
                        {
                            "id": self._ids.new("rlt"),
                            "key": hashed,
                            "count": 1,
                            "reset_at": now + window,
                        },
                    )
                except UniqueViolation:
                    continue
                return 1 <= rule.max, max(1, math.ceil(window.total_seconds()))
            if now >= row["reset_at"]:
                new = {"count": 1, "reset_at": now + window}
            else:
                new = {"count": row["count"] + 1}
            updated = await self._adapter.update(
                "rate_limit",
                [Where("id", row["id"]), Where("count", row["count"])],
                new,
            )
            if updated is None:
                continue
            retry = max(1, math.ceil((updated["reset_at"] - now).total_seconds()))
            return updated["count"] <= rule.max, retry
        # Fail closed under extreme contention.
        return False, 1
