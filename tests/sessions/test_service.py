"""The session service: tokens, expiry, sliding refresh, cookies, caches."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import SessionService, Where
from gotauth.contracts.endpoints import Plugin
from gotauth.contracts.schema import Field, ModelSchema
from gotauth.sessions import (
    SESSION_PREFIX,
    DefaultSessionService,
    memory_secondary_storage,
    session_principal,
    session_service,
)
from gotauth.testing import FakeContext

from .conftest import new_user, session_ctx, session_row

COOKIE = "gotauth.session_token"
CACHE = "gotauth.session_data"


def test_service_satisfies_the_protocol() -> None:
    assert isinstance(DefaultSessionService(), SessionService)


async def test_create_stores_only_the_hash() -> None:
    ctx = session_ctx()
    user_id = await new_user(ctx)
    created = await ctx.sessions.create(ctx, user_id)
    assert created.token.startswith(SESSION_PREFIX)
    row = await session_row(ctx, created.session.id)
    assert row is not None
    assert row["token_hash"] == ctx.crypto.hash_token(created.token)
    assert "token_hash" not in created.session.model_dump()


async def test_no_raw_token_anywhere_after_the_full_lifecycle() -> None:
    ctx = session_ctx(secondary=memory_secondary_storage())
    user_id = await new_user(ctx)
    created = await ctx.sessions.create(ctx, user_id)
    ctx.clock.advance("2d")
    assert await ctx.sessions.get(ctx, created.token) is not None  # slides
    other = await ctx.sessions.create(ctx, user_id)
    await ctx.sessions.revoke(ctx, other.session.id)
    dumped = json.dumps(await ctx.dump(), default=str)
    assert created.token not in dumped
    assert other.token not in dumped
    assert SESSION_PREFIX not in dumped


async def test_each_create_makes_a_new_token_even_when_one_is_presented() -> None:
    ctx = session_ctx()
    user_id = await new_user(ctx)
    first = await ctx.sessions.create(ctx, user_id)
    again = ctx.next_request(cookies={COOKIE: first.token})
    second = await again.sessions.create(again, user_id)
    assert second.token != first.token
    assert second.session.id != first.session.id


NOTE = Plugin(
    id="note",
    schema={
        "session": ModelSchema(
            name="session", fields={"note": Field(type="string", required=False)}
        )
    },
)


async def test_create_records_request_details_and_extra() -> None:
    ctx = session_ctx(user_agent="x" * 2000, plugins=(NOTE,))
    user_id = await new_user(ctx)
    created = await ctx.sessions.create(ctx, user_id, extra={"note": "hi"})
    row = await session_row(ctx, created.session.id)
    assert row is not None
    assert row["user_agent"] == "x" * 512
    assert row["ip_address"] == "127.0.0.1"
    assert row["note"] == "hi"


async def test_lifetimes() -> None:
    ctx = session_ctx()
    user_id = await new_user(ctx)
    now = ctx.clock.now()
    long = await ctx.sessions.create(ctx, user_id)
    short = await ctx.sessions.create(ctx, user_id, remember_me=False)
    explicit = await ctx.sessions.create(ctx, user_id, expires_in="10m")
    assert long.session.expires_at == now + timedelta(days=7)
    assert short.session.expires_at == now + timedelta(days=1)
    assert explicit.session.expires_at == now + timedelta(minutes=10)


async def test_get_rejects_foreign_prefixes_and_unknown_tokens() -> None:
    ctx = session_ctx()
    await ctx.sessions.create(ctx, await new_user(ctx))
    assert await ctx.sessions.get(ctx, "gak_whatever") is None
    assert await ctx.sessions.get(ctx, SESSION_PREFIX + "unknown") is None


async def test_expired_sessions_are_deleted() -> None:
    ctx = session_ctx()
    created = await ctx.sessions.create(ctx, await new_user(ctx), expires_in="1h")
    ctx.clock.advance("1h")
    assert await ctx.sessions.get(ctx, created.token) is None
    assert await session_row(ctx, created.session.id) is None


async def test_sessions_of_deleted_users_are_not_returned() -> None:
    ctx = session_ctx()
    user_id = await new_user(ctx)
    created = await ctx.sessions.create(ctx, user_id)
    await ctx.adapter.delete("user", [Where("id", user_id)])
    assert await ctx.sessions.get(ctx, created.token) is None


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    remember_me=st.booleans(),
    explicit=st.sampled_from([None, "30m", "12h"]),
    steps=st.lists(
        st.integers(min_value=0, max_value=3 * 86_400), min_size=1, max_size=8
    ),
)
async def test_expiry_and_refresh_properties(
    remember_me: bool, explicit: str | None, steps: list[int]
) -> None:
    ctx = session_ctx()
    created = await ctx.sessions.create(
        ctx, await new_user(ctx), remember_me=remember_me, expires_in=explicit
    )
    update_age = timedelta(days=1)
    short = timedelta(days=1)
    for seconds in steps:
        before = await session_row(ctx, created.session.id)
        ctx.clock.advance(seconds)
        now = ctx.clock.now()
        found = await ctx.sessions.get(ctx, created.token)
        if before is None:
            assert found is None
            continue
        # get returns None iff now >= expires_at
        assert (found is None) == (now >= before["expires_at"])
        after = await session_row(ctx, created.session.id)
        if found is None:
            assert after is None
            continue
        assert after is not None
        # expires_at never moves backwards
        assert after["expires_at"] >= before["expires_at"]
        refreshed = after["updated_at"] != before["updated_at"]
        # refresh only after update_age
        assert refreshed == (now - before["updated_at"] >= update_age)
        if not remember_me:
            assert after["expires_at"] <= after["updated_at"] + short
        if explicit is not None and refreshed:
            # a session that slides gets the normal lifetime, never shorter
            assert after["expires_at"] >= before["expires_at"]
        # never past the absolute lifetime (30 days by default)
        assert after["expires_at"] <= after["created_at"] + timedelta(days=30)


async def test_explicit_lifetime_shorter_than_update_age_never_slides() -> None:
    ctx = session_ctx()
    created = await ctx.sessions.create(ctx, await new_user(ctx), expires_in="30m")
    for _ in range(5):
        ctx.clock.advance("5m")
        found = await ctx.sessions.get(ctx, created.token)
        assert found is not None
        assert found.session.expires_at == created.session.expires_at
    ctx.clock.advance("5m")
    assert await ctx.sessions.get(ctx, created.token) is None


async def test_concurrent_gets_refresh_exactly_once() -> None:
    ctx = session_ctx()
    created = await ctx.sessions.create(ctx, await new_user(ctx))
    ctx.clock.advance("2d")
    updates = 0
    adapter = ctx.adapter
    original = adapter.update

    async def counting(*args: object, **kwargs: object) -> object:
        nonlocal updates
        result = await original(*args, **kwargs)  # type: ignore[arg-type]
        if result is not None:
            updates += 1
        return result

    adapter.update = counting  # type: ignore[method-assign]
    contexts = [ctx.next_request() for _ in range(20)]
    results = await asyncio.gather(
        *(c.sessions.get(c, created.token) for c in contexts)
    )
    assert all(result is not None for result in results)
    assert updates == 1
    assert sum(1 for c in contexts if c.cookies) == 1  # only the refresh re-sets it


@pytest.mark.parametrize(
    ("base_url", "name", "secure"),
    [
        ("https://app.example.com", "__Secure-" + COOKIE, True),
        ("http://localhost:8000", COOKIE, False),
        ("http://127.0.0.1:9000", COOKIE, False),
    ],
)
async def test_cookie_attributes(base_url: str, name: str, secure: bool) -> None:
    ctx = session_ctx(base_url=base_url)
    user_id = await new_user(ctx)
    created = await ctx.sessions.create(ctx, user_id)
    cookie = ctx.cookies[-1]
    assert cookie.name == name
    assert cookie.value == created.token
    assert cookie.secure is secure
    assert cookie.http_only
    assert cookie.same_site == "lax"
    assert cookie.path == "/"
    assert cookie.max_age == 7 * 86_400
    await ctx.sessions.create(ctx, user_id, remember_me=False)
    assert ctx.cookies[-1].max_age is None


async def test_clear_cookies_deletes_both_cookies() -> None:
    ctx = session_ctx(base_url="https://app.example.com")
    ctx.sessions.clear_cookies(ctx)
    assert {(c.name, c.max_age, c.secure) for c in ctx.cookies} == {
        ("__Secure-" + COOKIE, 0, True),
        ("__Secure-" + CACHE, 0, True),
    }


async def test_list_revoke_and_revoke_all() -> None:
    ctx = session_ctx()
    user_id = await new_user(ctx)
    stranger = await new_user(ctx, "bob@example.com")
    first = await ctx.sessions.create(ctx, user_id)
    ctx.clock.advance("1m")
    second = await ctx.sessions.create(ctx, user_id)
    ctx.clock.advance("1m")
    third = await ctx.sessions.create(ctx, user_id)
    theirs = await ctx.sessions.create(ctx, stranger)
    listed = await ctx.sessions.list_for_user(ctx, user_id)
    assert [s.id for s in listed] == [
        third.session.id,
        second.session.id,
        first.session.id,
    ]
    assert await ctx.sessions.revoke(ctx, first.session.id)
    assert not await ctx.sessions.revoke(ctx, first.session.id)
    assert ctx.event_types().count("session.revoked") == 1
    count = await ctx.sessions.revoke_all(
        ctx, user_id, except_session_id=third.session.id
    )
    assert count == 1
    assert [s.id for s in await ctx.sessions.list_for_user(ctx, user_id)] == [
        third.session.id
    ]
    assert await ctx.sessions.get(ctx, theirs.token) is not None
    assert await ctx.sessions.revoke_all(ctx, user_id) == 1
    assert await ctx.sessions.get(ctx, third.token) is None


# ---------------------------------------------------------------- cookie cache

CACHED = {"cookie_cache": {"enabled": True, "max_age": "5m"}}


async def cached_session(ctx: FakeContext) -> tuple[str, str]:
    created = await ctx.sessions.create(ctx, await new_user(ctx))
    value = ctx.cookie("session_data")
    assert value is not None
    return created.token, created.session.id


async def test_cache_is_off_by_default() -> None:
    ctx = session_ctx()
    await ctx.sessions.create(ctx, await new_user(ctx))
    assert ctx.cookie("session_data") is None


async def test_cache_skips_the_database_until_it_expires() -> None:
    ctx = session_ctx(session_config=CACHED)
    token, session_id = await cached_session(ctx)
    await ctx.sessions.revoke(ctx, session_id)
    later = ctx.next_request()
    # Revoked, but the cache is still valid: the documented revocation delay.
    assert await later.sessions.get(later, token) is not None
    ctx.clock.advance("5m")
    expired = later.next_request()
    assert await expired.sessions.get(expired, token) is None


async def test_tampered_cache_is_ignored() -> None:
    ctx = session_ctx(session_config=CACHED)
    token, session_id = await cached_session(ctx)
    await ctx.sessions.revoke(ctx, session_id)
    value = ctx.cookie("session_data")
    assert value is not None
    flipped = value[:-1] + ("A" if value[-1] != "A" else "B")
    later = ctx.next_request(cookies={CACHE: flipped})
    assert await later.sessions.get(later, token) is None


async def test_cache_only_works_with_its_own_token() -> None:
    ctx = session_ctx(session_config=CACHED)
    user_id = await new_user(ctx)
    victim = await ctx.sessions.create(ctx, user_id)
    cache = ctx.cookie("session_data")
    attacker_ctx = ctx.next_request()
    attacker = await attacker_ctx.sessions.create(
        attacker_ctx, await new_user(ctx, "eve@example.com")
    )
    await ctx.sessions.revoke(ctx, victim.session.id)
    assert cache is not None
    mixed = ctx.next_request(cookies={CACHE: cache})
    found = await mixed.sessions.get(mixed, attacker.token)
    assert found is not None
    assert found.user.id != user_id  # served from the database, not the foreign cache


async def test_oversized_cache_is_not_set() -> None:
    plugin = Plugin(
        id="big",
        schema={
            "user": ModelSchema(
                name="user", fields={"bio": Field(type="string", required=False)}
            )
        },
    )
    ctx = session_ctx(session_config=CACHED, plugins=(plugin,))
    user = await ctx.auth.create_user_record(
        ctx, {"email": "ada@example.com", "bio": "x" * 4000}
    )
    await ctx.sessions.create(ctx, user.id)
    assert ctx.cookie("session_token") is not None
    assert ctx.cookie("session_data") is None


# ---------------------------------------------------------------- secondary storage


async def test_secondary_storage_caches_by_hash_and_forgets_on_revoke() -> None:
    storage = memory_secondary_storage()
    ctx = session_ctx(secondary=storage)
    created = await ctx.sessions.create(ctx, await new_user(ctx))
    assert await ctx.sessions.get(ctx, created.token) is not None
    key = f"session:{ctx.crypto.hash_token(created.token)}"
    assert await storage.get(key) is not None
    await ctx.sessions.revoke(ctx, created.session.id)
    assert await storage.get(key) is None
    assert await ctx.sessions.get(ctx, created.token) is None


async def test_session_service_factory_takes_secondary_storage() -> None:
    storage = memory_secondary_storage()
    service = session_service(object(), secondary_storage=storage)  # type: ignore[arg-type]
    assert isinstance(service, DefaultSessionService)


# ---------------------------------------------------------------- principal


async def test_principal_copies_active_organization_id() -> None:
    plugin = Plugin(
        id="orgs",
        schema={
            "session": ModelSchema(
                name="session",
                fields={"active_organization_id": Field(type="string", required=False)},
            )
        },
    )
    ctx = session_ctx(plugins=(plugin,))
    created = await ctx.sessions.create(
        ctx, await new_user(ctx), extra={"active_organization_id": "org_1"}
    )
    found = await ctx.sessions.get(ctx, created.token)
    assert found is not None
    principal = session_principal(found.session)
    assert principal.organization_id == "org_1"
    assert principal.via == "session"
    assert principal.credential_id == created.session.id
    assert principal.scopes is None


async def test_sliding_never_passes_the_absolute_lifetime() -> None:
    # ASVS 7.3.2: a session used every day still ends 30 days after sign-in.
    ctx = session_ctx()
    created = await ctx.sessions.create(ctx, await new_user(ctx))
    for _ in range(29):
        ctx.clock.advance("1d")
        assert await ctx.sessions.get(ctx, created.token) is not None
    found = await ctx.sessions.get(ctx, created.token)
    assert found is not None
    assert found.session.expires_at == created.session.created_at + timedelta(days=30)
    ctx.clock.advance("1d")
    assert await ctx.sessions.get(ctx, created.token) is None


async def test_absolute_lifetime_can_be_turned_off() -> None:
    ctx = session_ctx(session_config={"absolute_lifetime": None})
    created = await ctx.sessions.create(ctx, await new_user(ctx))
    for _ in range(40):
        ctx.clock.advance("1d")
        assert await ctx.sessions.get(ctx, created.token) is not None
