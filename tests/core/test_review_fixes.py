"""Regression tests for the C1 code-review findings."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from gotauth.contracts import ConfigError, Plugin, RateLimitRule
from gotauth.contracts.protection import DEFAULT_RATE_LIMITS
from gotauth.core import GotAuth
from gotauth.core._ratelimit import select_rules
from gotauth.storage.memory import memory_adapter
from gotauth.testing import fake_clock, fake_sessions, seq_ids

from .conftest import build, endpoint

SECRET = "review-fix-tests-secret-0123456789ab"


def test_broad_config_rule_does_not_hide_specific_defaults() -> None:
    broad = RateLimitRule(path="*", window="60s", max=300, key="ip_path")
    chosen = select_rules(
        "/sign-in/email", [(), (), (broad,), DEFAULT_RATE_LIMITS], ["ip_path"]
    )
    assert chosen[0].path == "/sign-in/*"
    assert chosen[0].max == 5
    other = select_rules(
        "/anything", [(), (), (broad,), DEFAULT_RATE_LIMITS], ["ip_path"]
    )
    assert other == [broad]


def test_same_path_earlier_source_wins() -> None:
    mine = RateLimitRule(path="/sign-in/*", window="60s", max=2, key="ip_path")
    chosen = select_rules(
        "/sign-in/email", [(), (), (mine,), DEFAULT_RATE_LIMITS], ["ip_path"]
    )
    assert chosen == [mine]


class TokenQuery(BaseModel):
    token: str


async def test_server_call_reads_query_input() -> None:
    async def verify(ctx: Any, data: TokenQuery) -> dict[str, str]:
        return {"token": data.token}

    plugin = Plugin(
        id="q",
        endpoints=(endpoint("verify_q", "GET", "/verify-q", verify, input=TokenQuery),),
    )
    auth = build(plugin)
    assert await auth.api.call("verify_q", query={"token": "abc"}) == {"token": "abc"}


async def test_no_console_email_outside_localhost() -> None:
    auth = GotAuth(
        database=memory_adapter(),
        secret=SECRET,
        base_url="https://api.example.com",
        email_password={"enabled": False},
        advanced={"install_core_plugins": False, "session_service": fake_sessions()},
    )
    with pytest.raises(ConfigError, match="email sender"):
        await auth.email.send(
            "reset_password", "a@b.c", url="https://x/reset?token=secret"
        )


class FakeSecondary:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    async def get(self, key: str) -> str | None:
        return None

    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        return None

    async def delete(self, key: str) -> None:
        return None

    async def incr(self, key: str, ttl_seconds: int) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]


async def test_secondary_storage_retry_after_is_time_left() -> None:
    from gotauth.testing import make_client

    clock = fake_clock()
    clock.advance("50s")  # 10 s left in the current 60 s window
    auth = build(
        clock=clock,
        rate_limit={"storage": "secondary"},
        secondary_storage=FakeSecondary(),
    )
    async with make_client(auth) as client:
        for _ in range(3):  # the endpoint's own rule allows 3 per 60 s
            await client.post("/limited", json={"name": "a"})
        limited = await client.post("/limited", json={"name": "a"})
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "10"


async def test_memory_store_drops_expired_windows() -> None:
    from gotauth.core._ratelimit import RateLimiter

    clock = fake_clock()
    limiter = RateLimiter(
        enabled=True,
        storage="memory",
        clock=clock,
        ids=seq_ids(),
        config_rules=(),
        plugin_rules=(),
        adapter=memory_adapter(),
        secondary=None,
    )
    rule = RateLimitRule(path="*", window="60s", max=10, key="ip")
    for index in range(1500):
        await limiter._hit(f"k{index}", rule)  # pyright: ignore[reportPrivateUsage]
    clock.advance("2m")
    for index in range(1000):
        await limiter._hit(f"new{index}", rule)  # pyright: ignore[reportPrivateUsage]
    assert len(limiter._memory) <= 1000  # pyright: ignore[reportPrivateUsage]
