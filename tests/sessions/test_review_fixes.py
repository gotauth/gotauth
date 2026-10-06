"""Regression tests for the C3 code review findings."""

from __future__ import annotations

import json
from datetime import timedelta

from gotauth.sessions import memory_secondary_storage
from gotauth.testing import fake_clock, make_client

from .conftest import new_user, session_ctx, session_row
from .test_http import bearer, build, sign_in

COOKIE = "gotauth.session_token"


async def test_stale_secondary_copy_never_decides_expiry() -> None:
    clock = fake_clock()
    storage = memory_secondary_storage(clock=clock)
    ctx = session_ctx(secondary=storage, clock=clock)
    created = await ctx.sessions.create(ctx, await new_user(ctx))
    key = f"session:{ctx.crypto.hash_token(created.token)}"
    stale = await session_row(ctx, created.session.id)
    assert stale is not None
    ctx.clock.advance("1d")
    assert await ctx.sessions.get(ctx, created.token) is not None
    # The database row was extended; plant the old copy, as a slow request would.
    fresh = await session_row(ctx, created.session.id)
    assert fresh is not None
    assert fresh["expires_at"] > stale["expires_at"]
    await storage.set(key, json.dumps(stale, default=str), 30 * 86_400)
    ctx.clock.set(stale["expires_at"])
    assert await ctx.sessions.get(ctx, created.token) is not None
    assert await session_row(ctx, created.session.id) is not None


async def test_lost_refresh_race_drops_the_cached_copy() -> None:
    clock = fake_clock()
    storage = memory_secondary_storage(clock=clock)
    ctx = session_ctx(secondary=storage, clock=clock)
    created = await ctx.sessions.create(ctx, await new_user(ctx))
    key = f"session:{ctx.crypto.hash_token(created.token)}"
    ctx.clock.advance("2d")
    row = await session_row(ctx, created.session.id)
    assert row is not None
    original = ctx.adapter.update

    async def lose(*args: object, **kwargs: object) -> None:
        return None  # another request won the compare-and-set

    ctx.adapter.update = lose  # type: ignore[method-assign]
    await storage.set(key, json.dumps(row, default=str), 10_000)
    assert await ctx.sessions.get(ctx, created.token) is not None
    assert await storage.get(key) is None
    ctx.adapter.update = original  # type: ignore[method-assign]


async def test_secondary_ttl_is_capped() -> None:
    clock = fake_clock()
    storage = memory_secondary_storage(clock=clock)
    ctx = session_ctx(secondary=storage, clock=clock)
    created = await ctx.sessions.create(ctx, await new_user(ctx))
    key = f"session:{ctx.crypto.hash_token(created.token)}"
    assert await ctx.sessions.get(ctx, created.token) is not None
    assert await storage.get(key) is not None
    ctx.clock.advance(timedelta(seconds=300))
    assert await storage.get(key) is None


async def test_bearer_reads_never_set_cookies() -> None:
    ctx = session_ctx(session_config={"cookie_cache": {"enabled": True}})
    user_id = await new_user(ctx)
    created = await ctx.sessions.create(ctx, user_id)
    ctx.clock.advance("2d")
    other = ctx.next_request(cookies={COOKIE: "gas_someone_else"})
    found = await other.sessions.get(other, created.token)
    assert found is not None
    assert found.session.updated_at == ctx.clock.now()  # refreshed in the database
    assert other.cookies == []


async def test_get_session_with_x_api_key() -> None:
    auth = build()
    async with make_client(auth) as client:
        token = await sign_in(client)
        client.cookies.clear()
        body = (await client.get("/session", headers={"x-api-key": token})).json()
        assert body is not None
        assert body["user"]["email"] == "ada@example.com"
        await sign_in(client, "bob@example.com")
        # A bearer token wins over a cookie for another session, as in the pipeline.
        mixed = (await client.get("/session", headers=bearer(token))).json()
    assert mixed["user"]["email"] == "ada@example.com"
