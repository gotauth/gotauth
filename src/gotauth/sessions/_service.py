"""The session service (CONTRACTS 7)."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from gotauth.contracts.adapter import Where
from gotauth.contracts.config import ResolvedConfig
from gotauth.contracts.core_schema import Session, User
from gotauth.contracts.endpoints import EndpointContext
from gotauth.contracts.http import SetCookie
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.schema import returned_only
from gotauth.contracts.sessions import (
    TOKEN_PREFIXES,
    CreatedSession,
    SecondaryStorage,
    SessionWithUser,
    cookie_name,
    secure_cookies,
)

__all__ = ["SESSION_PREFIX", "DefaultSessionService", "session_service"]

SESSION_PREFIX = TOKEN_PREFIXES["session_token"]
_USER_AGENT_LIMIT = 512
_CACHE_LIMIT = 3500  # bytes; larger cache cookies are skipped
_SECONDARY_TTL = 300  # seconds; bounds staleness after direct writes to a session row


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(type(value).__name__)


class DefaultSessionService:
    """Sessions in the database; tokens hashed at rest, cookie or bearer.

    Optional layers: a signed cookie cache (``sessions.cookie_cache``) and a
    secondary-storage cache keyed by token hash. Both are dropped on revocation, but a
    cookie cache can only expire: revocation takes up to ``cookie_cache.max_age``.
    """

    def __init__(self, secondary: SecondaryStorage | None = None) -> None:
        self._secondary = secondary

    # ------------------------------------------------------------ create

    async def create(
        self,
        ctx: EndpointContext,
        user_id: str,
        *,
        remember_me: bool = True,
        expires_in: Duration | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> CreatedSession:
        """Create a session with a fresh token and set its cookie."""
        config = ctx.auth.config.sessions
        now = ctx.clock.now()
        if expires_in is not None:
            lifetime = to_timedelta(expires_in)
        elif remember_me:
            lifetime = to_timedelta(config.expires_in)
        else:
            lifetime = to_timedelta(config.short_expires_in)
        # Always a new token: a token from the request is never reused (fixation).
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
        if config.cookie_cache.enabled:
            user = await self._user(ctx, user_id)
            if user is not None:
                self._set_cache(ctx, token, session, user)
        return CreatedSession(session=session, token=token)

    # ------------------------------------------------------------ read

    async def get(self, ctx: EndpointContext, token: str) -> SessionWithUser | None:
        """Return the session for a raw token, or ``None``; expired rows are deleted.

        Cookies are written only when ``token`` is the request's session cookie, so a
        bearer request never changes the browser's cookie session.
        """
        if not token.startswith(SESSION_PREFIX):
            return None
        from_cookie = self._is_cookie_token(ctx, token)
        if from_cookie:
            cached = self._from_cookie_cache(ctx, token)
            if cached is not None:
                return cached
        token_hash = ctx.crypto.hash_token(token)
        now = ctx.clock.now()
        row = await self._find(ctx, token_hash, now)
        if row is None:
            return None
        if now >= row["expires_at"]:
            await ctx.adapter.delete("session", [Where("id", row["id"])])
            await self._forget(token_hash)
            return None
        user = await self._user(ctx, row["user_id"])
        if user is None:
            return None
        slid = await self._slide(ctx, row, now)
        if slid is not None:
            await self._remember(token_hash, slid, now)
        elif self._due(ctx, row, now):
            # Another request refreshed it first; drop any copy older than its write.
            await self._forget(token_hash)
        session = Session.model_validate(
            returned_only(ctx.auth.schema["session"], slid or row)
        )
        if from_cookie:
            if slid is not None:
                self._set_cookie(ctx, token, session)
            if ctx.auth.config.sessions.cookie_cache.enabled:
                self._set_cache(ctx, token, session, user)
        return SessionWithUser(session=session, user=user)

    def _is_cookie_token(self, ctx: EndpointContext, token: str) -> bool:
        cookie = ctx.request.cookies.get(self._name(ctx, "session_token"))
        return cookie is not None and ctx.crypto.equal(cookie, token)

    @staticmethod
    def _due(ctx: EndpointContext, row: Mapping[str, Any], now: datetime) -> bool:
        update_age = to_timedelta(ctx.auth.config.sessions.update_age)
        return now - row["updated_at"] >= update_age

    async def _find(
        self, ctx: EndpointContext, token_hash: str, now: datetime
    ) -> dict[str, Any] | None:
        if self._secondary is not None:
            raw = await self._secondary.get(f"session:{token_hash}")
            if raw is not None:
                data = json.loads(raw)
                for key in ("expires_at", "created_at", "updated_at"):
                    data[key] = datetime.fromisoformat(data[key])
                # Expiry and refresh are decided on the database row, never on a copy.
                if (
                    ctx.crypto.equal(data.get("token_hash", ""), token_hash)
                    and now < data["expires_at"]
                    and not self._due(ctx, data, now)
                ):
                    return data
        row = await ctx.adapter.find_one("session", [Where("token_hash", token_hash)])
        if row is None or not ctx.crypto.equal(row["token_hash"], token_hash):
            return None
        if not self._due(ctx, row, now):
            await self._remember(token_hash, row, now)
        return row

    async def _remember(
        self, token_hash: str, row: Mapping[str, Any], now: datetime
    ) -> None:
        if self._secondary is None:
            return
        remaining = int((row["expires_at"] - now).total_seconds())  # rounds down
        ttl = min(remaining, _SECONDARY_TTL)
        if ttl > 0:
            await self._secondary.set(
                f"session:{token_hash}",
                json.dumps(dict(row), default=_json_default),
                ttl,
            )

    async def _forget(self, token_hash: str) -> None:
        if self._secondary is not None:
            await self._secondary.delete(f"session:{token_hash}")

    @staticmethod
    async def _user(ctx: EndpointContext, user_id: str) -> User | None:
        row = await ctx.adapter.find_one("user", [Where("id", user_id)])
        if row is None:
            return None
        return User.model_validate(returned_only(ctx.auth.schema["user"], row))

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
        """Return the user's sessions, newest first."""
        rows = await ctx.adapter.find_many("session", [Where("user_id", user_id)])
        rows.sort(key=lambda row: row["created_at"], reverse=True)
        return [
            Session.model_validate(returned_only(ctx.auth.schema["session"], row))
            for row in rows
        ]

    # ------------------------------------------------------------ revoke

    async def revoke(self, ctx: EndpointContext, session_id: str) -> bool:
        """Delete one session and emit ``session.revoked``."""
        row = await ctx.adapter.find_one("session", [Where("id", session_id)])
        if row is None:
            return False
        deleted = await ctx.adapter.delete("session", [Where("id", session_id)])
        await self._forget(row["token_hash"])
        if deleted:
            await ctx.emit(
                "session.revoked", session_id=session_id, user_id=row["user_id"]
            )
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
        rows = await ctx.adapter.find_many("session", where)
        count = await ctx.adapter.delete("session", where)
        for row in rows:
            await self._forget(row["token_hash"])
        if count:
            await ctx.emit("session.revoked", user_id=user_id, count=count)
        return count

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

    # ------------------------------------------------------------ cookies

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

    def _set_cache(
        self, ctx: EndpointContext, token: str, session: Session, user: User
    ) -> None:
        max_age = to_timedelta(ctx.auth.config.sessions.cookie_cache.max_age)
        exp = ctx.clock.now() + max_age
        payload = {
            "session": session.model_dump(mode="json"),
            "user": user.model_dump(mode="json"),
            "exp": int(exp.timestamp()),
            # Binds the cache to its own session token.
            "th": ctx.crypto.hash_token(token),
        }
        value = ctx.crypto.sign(
            _b64(json.dumps(payload).encode()), purpose="session_data"
        )
        if len(value) > _CACHE_LIMIT:
            return
        ctx.set_cookie(
            SetCookie(
                name=self._name(ctx, "session_data"),
                value=value,
                max_age=int(max_age.total_seconds()),
                secure=secure_cookies(ctx.auth.config.base_url),
            )
        )

    def _from_cookie_cache(
        self, ctx: EndpointContext, token: str
    ) -> SessionWithUser | None:
        if not ctx.auth.config.sessions.cookie_cache.enabled:
            return None
        raw = ctx.request.cookies.get(self._name(ctx, "session_data"))
        if not raw:
            return None
        encoded = ctx.crypto.unsign(raw, purpose="session_data")
        if encoded is None:
            return None
        try:
            payload = json.loads(_unb64(encoded))
            if not ctx.crypto.equal(str(payload["th"]), ctx.crypto.hash_token(token)):
                return None
            now = ctx.clock.now()
            if now >= datetime.fromtimestamp(int(payload["exp"]), tz=UTC):
                return None
            session = Session.model_validate(payload["session"])
            if now >= session.expires_at:
                return None
            return SessionWithUser(
                session=session, user=User.model_validate(payload["user"])
            )
        except (ValueError, KeyError, TypeError):
            return None


def session_service(
    config: ResolvedConfig, *, secondary_storage: SecondaryStorage | None = None
) -> DefaultSessionService:
    """Build the session service (CONTRACTS 13.2). Config is read per request."""
    del config  # settings are read from ctx.auth.config at request time
    return DefaultSessionService(secondary_storage)
