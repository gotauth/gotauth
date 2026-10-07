"""Single-use verification tokens (``gav_...``), stored only as hashes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from gotauth.contracts.adapter import Where
from gotauth.contracts.endpoints import EndpointContext
from gotauth.contracts.errors import AuthError
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.sessions import TOKEN_PREFIXES

__all__ = ["VERIFICATION_PREFIX", "Consumed", "consume_token", "issue_token"]

VERIFICATION_PREFIX = TOKEN_PREFIXES["verification_token"]


@dataclass(frozen=True)
class Consumed:
    """A consumed token: its kind, the user it was issued for and its data."""

    kind: str
    user_id: str
    data: Mapping[str, Any]  # Any: JSON data stored with the token


async def issue_token(
    ctx: EndpointContext,
    kind: str,
    user_id: str,
    expires_in: Duration,
    data: Mapping[str, Any] | None = None,  # Any: JSON data
) -> str:
    """Create a token for ``<kind>:<user_id>``; older tokens of that identifier go."""
    identifier = f"{kind}:{user_id}"
    await ctx.adapter.delete("verification", [Where("identifier", identifier)])
    token = ctx.crypto.random_token(VERIFICATION_PREFIX)
    now = ctx.clock.now()
    await ctx.adapter.create(
        "verification",
        {
            "id": ctx.ids.new("ver"),
            "identifier": identifier,
            "value_hash": ctx.crypto.hash_token(token),
            "expires_at": now + to_timedelta(expires_in),
            "created_at": now,
            "data": dict(data) if data else None,
        },
    )
    return token


async def consume_token(
    ctx: EndpointContext, token: str, kinds: tuple[str, ...]
) -> Consumed:
    """Consume a token once.

    Raises:
        AuthError: TOKEN_INVALID for unknown, used or wrong-kind tokens; TOKEN_EXPIRED
            when the token exists but has expired.
    """
    if not token.startswith(VERIFICATION_PREFIX):
        raise AuthError("TOKEN_INVALID", 400)
    value_hash = ctx.crypto.hash_token(token)
    row = await ctx.adapter.find_one("verification", [Where("value_hash", value_hash)])
    if row is None:
        raise AuthError("TOKEN_INVALID", 400)
    kind, _, user_id = str(row["identifier"]).partition(":")
    if kind not in kinds or not user_id:
        raise AuthError("TOKEN_INVALID", 400)
    now = ctx.clock.now()
    deleted = await ctx.adapter.delete(
        "verification",
        [
            Where("id", row["id"]),
            Where("value_hash", value_hash),
            Where("expires_at", now, op="gt"),
        ],
    )
    if deleted != 1:
        if now >= row["expires_at"]:
            raise AuthError("TOKEN_EXPIRED", 400)
        raise AuthError("TOKEN_INVALID", 400)
    data: dict[str, Any] = row.get("data") or {}  # Any: JSON data
    return Consumed(kind=kind, user_id=user_id, data=data)
