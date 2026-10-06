"""Helpers for the session tests: a fake context on the real session service."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from gotauth.contracts import Plugin, SecondaryStorage, Where
from gotauth.sessions import DefaultSessionService
from gotauth.testing import FakeContext, ManualClock, make_context


def session_ctx(
    *,
    session_config: Mapping[str, Any] | None = None,
    secondary: SecondaryStorage | None = None,
    base_url: str = "http://localhost:8000",
    plugins: tuple[Plugin, ...] = (),
    user_agent: str | None = None,
    clock: ManualClock | None = None,
) -> FakeContext:
    """Return a context whose ``ctx.sessions`` is the real C3 service."""
    ctx = make_context(
        sessions=DefaultSessionService(secondary),
        session_config=session_config,
        base_url=base_url,
        plugins=plugins,
        clock=clock,
    )
    if user_agent is not None:
        ctx = ctx.next_request(headers={"user-agent": user_agent})
    return ctx


async def new_user(ctx: FakeContext, email: str = "ada@example.com") -> str:
    """Create a user and return its id."""
    user = await ctx.auth.create_user_record(ctx, {"email": email})
    return user.id


async def session_row(ctx: FakeContext, session_id: str) -> dict[str, Any] | None:
    """Return the stored session row."""
    return await ctx.adapter.find_one("session", [Where("id", session_id)])
