"""A session service for unit tests, before C3 merges."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from gotauth.contracts.adapter import Where
from gotauth.contracts.core_schema import Session, User
from gotauth.contracts.endpoints import EndpointContext
from gotauth.contracts.http import SetCookie
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.schema import returned_only
from gotauth.contracts.sessions import (
    TOKEN_PREFIXES,
    CreatedSession,
    SessionWithUser,
    cookie_name,
    secure_cookies,
)

__all__ = ["FakeSessionService", "fake_sessions"]

SESSION_PREFIX = TOKEN_PREFIXES["session_token"]
_USER_AGENT_LIMIT = 512


class FakeSessionService:
    """A ``SessionService`` storing sessions in ``ctx.adapter``, like C3 will.

    Tokens are ``gas_`` + 32 random bytes from ``ctx.crypto``; only their SHA-256
    hash is stored. ``remember_me`` is stored on the row. Cookies use the section 7
    names through
    ``cookie_name`` (``gotauth.session_token``, ``__Secure-`` on https). Sessions slide
    forward on ``get`` once ``update_age`` has passed. It does not implement the cookie
    cache or secondary storage.
    """

    async def create(
        self,
        ctx: EndpointContext,
        user_id: str,
        *,
        remember_me: bool = True,
        expires_in: Duration | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> CreatedSession:
        """Create a session with a new token and set the session cookie."""
        config = ctx.auth.config.sessions
        now = ctx.clock.now()
        if expires_in is not None:
            lifetime = to_timedelta(expires_in)
        elif remember_me:
            lifetime = to_timedelta(config.expires_in)
        else:
            lifetime = to_timedelta(config.short_expires_in)
        token = ctx.crypto.random_token(SESSION_PREFIX)
        user_agent = ctx.request.headers.get("user-agent")
        row = await ctx.adapter.create(
            "session",
            {
                "id": ctx.ids.new("ses"),
                "user_id": user_id,
                "token_hash": ctx.crypto.hash_token(token),
                "expires_at": now + lifetime,
                "remember_me": remember_me,
                "created_at": now,
                "updated_at": now,
                "ip_address": ctx.request.client_ip,
                "user_agent": user_agent[:_USER_AGENT_LIMIT] if user_agent else None,
                **(extra or {}),
            },
        )
        session = Session.model_validate(returned_only(ctx.auth.schema["session"], row))
        self._set_cookie(ctx, token, session)
        return CreatedSession(session=session, token=token)

    async def get(self, ctx: EndpointContext, token: str) -> SessionWithUser | None:
        """Return the session for a raw token, or ``None``; expired rows are deleted."""
        if not token.startswith(SESSION_PREFIX):
            return None
        token_hash = ctx.crypto.hash_token(token)
        row = await ctx.adapter.find_one("session", [Where("token_hash", token_hash)])
        if row is None or not ctx.crypto.equal(row["token_hash"], token_hash):
            return None
        now = ctx.clock.now()
        if now >= row["expires_at"]:
            await ctx.adapter.delete("session", [Where("id", row["id"])])
            return None
        user_row = await ctx.adapter.find_one("user", [Where("id", row["user_id"])])
        if user_row is None:
            return None
        slid = await self._slide(ctx, row, now)
        session = Session.model_validate(
            returned_only(ctx.auth.schema["session"], slid or row)
        )
        if slid is not None:
            self._set_cookie(ctx, token, session)
        user = User.model_validate(returned_only(ctx.auth.schema["user"], user_row))
        return SessionWithUser(session=session, user=user)

    async def _slide(
        self, ctx: EndpointContext, row: dict[str, Any], now: datetime
    ) -> dict[str, Any] | None:
        config = ctx.auth.config.sessions
        if now - row["updated_at"] < to_timedelta(config.update_age):
            return None
        lifetime = config.expires_in if row["remember_me"] else config.short_expires_in
        expires_at = max(row["expires_at"], now + to_timedelta(lifetime))
        # Compare-and-set on updated_at: concurrent reads refresh once.
        return await ctx.adapter.update(
            "session",
            [Where("id", row["id"]), Where("updated_at", row["updated_at"])],
            {"updated_at": now, "expires_at": expires_at},
        )

    async def list_for_user(self, ctx: EndpointContext, user_id: str) -> list[Session]:
        """Return the user's sessions."""
        rows = await ctx.adapter.find_many("session", [Where("user_id", user_id)])
        return [
            Session.model_validate(returned_only(ctx.auth.schema["session"], row))
            for row in rows
        ]

    async def revoke(self, ctx: EndpointContext, session_id: str) -> bool:
        """Delete one session and emit ``session.revoked``."""
        deleted = await ctx.adapter.delete("session", [Where("id", session_id)])
        if deleted:
            await ctx.emit("session.revoked", session_id=session_id)
        return deleted == 1

    async def revoke_all(
        self,
        ctx: EndpointContext,
        user_id: str,
        *,
        except_session_id: str | None = None,
    ) -> int:
        """Delete the user's sessions, optionally keeping one."""
        where = [Where("user_id", user_id)]
        if except_session_id is not None:
            where.append(Where("id", except_session_id, op="ne"))
        return await ctx.adapter.delete("session", where)

    def clear_cookies(self, ctx: EndpointContext) -> None:
        """Delete the session and cookie-cache cookies."""
        for base in ("session_token", "session_data"):
            ctx.set_cookie(
                SetCookie(
                    name=self._name(ctx, base),
                    value="",
                    max_age=0,
                    secure=secure_cookies(ctx.auth.config.base_url),
                )
            )

    @staticmethod
    def _name(ctx: EndpointContext, base: str) -> str:
        config = ctx.auth.config
        return cookie_name(
            base, base_url=config.base_url, prefix=config.advanced.cookie_prefix
        )

    def _set_cookie(self, ctx: EndpointContext, token: str, session: Session) -> None:
        max_age: int | None = None
        if session.remember_me:
            remaining = session.expires_at - ctx.clock.now()
            max_age = max(0, int(remaining / timedelta(seconds=1)))
        ctx.set_cookie(
            SetCookie(
                name=self._name(ctx, "session_token"),
                value=token,
                max_age=max_age,
                secure=secure_cookies(ctx.auth.config.base_url),
                http_only=True,
                same_site="lax",
            )
        )


def fake_sessions() -> FakeSessionService:
    """Return an in-memory session service with C3's token format and cookie names."""
    return FakeSessionService()
