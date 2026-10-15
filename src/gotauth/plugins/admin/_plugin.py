"""The ``admin`` plugin (work package P6): user management for app administrators,
bans checked on every sign-in and request, and audited impersonation."""

from __future__ import annotations

import weakref
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Generic, Literal, TypeVar

from gotauth.contracts.adapter import SortBy, Where
from gotauth.contracts.config import DatabaseHooks, ModelHooks
from gotauth.contracts.core_schema import User
from gotauth.contracts.endpoints import (
    Endpoint,
    EndpointContext,
    Hook,
    HookPayload,
    Plugin,
)
from gotauth.contracts.errors import AuthError, ConfigError, UniqueViolation
from gotauth.contracts.http import SetCookie
from gotauth.contracts.http_models import StatusOut
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.principal import Principal
from gotauth.contracts.schema import Field, ModelSchema, Reference
from gotauth.contracts.sessions import cookie_name, secure_cookies

from ._models import (
    AdminSessionListOut,
    AdminSessionOut,
    AdminUserOut,
    BanUserIn,
    CreateUserIn,
    ImpersonateOut,
    ListUsersIn,
    RevokedOut,
    RevokeUserSessionsIn,
    SetUserPasswordIn,
    SetUserRoleIn,
    StopImpersonatingOut,
    UserListOut,
)

__all__ = ["IMPERSONATION_BLOCKED", "admin"]

USER_FIELDS = ModelSchema(
    name="user",
    fields=MappingProxyType(
        {
            # Optional columns, so the plugin can be added to a table that has rows;
            # NULL reads as "user" and as not banned.
            "role": Field(
                "string", required=False, default="user", input=False, max_length=32
            ),
            "banned": Field("boolean", required=False, default=False, input=False),
            "ban_reason": Field(
                "string", required=False, input=False, returned=False, max_length=500
            ),
            "ban_expires_at": Field(
                "datetime", required=False, input=False, returned=False
            ),
        }
    ),
)
SESSION_FIELDS = ModelSchema(
    name="session",
    fields=MappingProxyType(
        {
            "impersonated_by": Field(
                "string",
                required=False,
                input=False,
                references=Reference("user", on_delete="set_null"),
            )
        }
    ),
)

ERROR_CODES: dict[str, tuple[int, str]] = {
    "ADMIN_USER_BANNED": (403, "This account is banned"),
    "ADMIN_CANNOT_TARGET_SELF": (400, "Admins cannot do this to their own account"),
    "ADMIN_CANNOT_IMPERSONATE_ADMIN": (403, "Admins cannot impersonate other admins"),
    "ADMIN_NOT_IMPERSONATING": (400, "This session is not an impersonation"),
    "ADMIN_IMPERSONATION_BLOCKED": (403, "Not allowed while impersonating a user"),
}

IMPERSONATION_BLOCKED: tuple[str, ...] = (
    # Credentials that would outlive the impersonation.
    "create_api_key",
    "update_api_key",
    "create_agent",
    "create_agent_api_key",
    "update_agent",
    "link_oauth_client",
    "create_oauth_client",
    "rotate_oauth_client_secret",
    "oauth_authorize",
    "oauth_consent",
    # The account's own security settings.
    "change_password",
    "change_email",
    "delete_user",
    "enable_two_factor",
    "disable_two_factor",
    "regenerate_backup_codes",
    "get_passkey_registration_options",
    "verify_passkey_registration",
    "delete_passkey",
    "link_social",
    "unlink_account",
)
"""Endpoint ids an impersonation session may not call by default."""

CREDENTIAL_PROVIDER = "credential"
BAN_CACHE_TTL = timedelta(seconds=5)
_CACHE_LIMIT = 10_000

Gone = Literal["gone"]
"""An uncached session whose row no longer exists (served by the cookie cache)."""

K = TypeVar("K")
V = TypeVar("V")


def _error(code: str) -> AuthError:
    status, message = ERROR_CODES[code]
    return AuthError(code, status, message)


class _Lru(Generic[K, V]):
    """A small least-recently-used map."""

    def __init__(self, limit: int = _CACHE_LIMIT) -> None:
        self._items: OrderedDict[K, V] = OrderedDict()
        self._limit = limit

    def __contains__(self, key: K) -> bool:
        return key in self._items

    def get(self, key: K) -> V | None:
        if key not in self._items:
            return None
        self._items.move_to_end(key)
        return self._items[key]

    def put(self, key: K, value: V) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        if len(self._items) > self._limit:
            self._items.popitem(last=False)

    def pop(self, key: K) -> None:
        self._items.pop(key, None)


@dataclass
class _State:
    """Per-``GotAuth`` caches. Bans are cached for ``BAN_CACHE_TTL``. Whether a session
    is an impersonation never changes, so that is kept, revoked sessions included: a
    session the cookie cache still serves stays marked."""

    bans: _Lru[str, tuple[bool, datetime | None, datetime]] = field(
        default_factory=_Lru[str, tuple[bool, datetime | None, datetime]]
    )
    impersonations: _Lru[str, tuple[str, datetime] | None] = field(
        default_factory=_Lru[str, tuple[str, datetime] | None]
    )


def _user_out(row: Mapping[str, Any]) -> AdminUserOut:
    return AdminUserOut(
        id=row["id"],
        email=row["email"],
        email_verified=bool(row.get("email_verified")),
        name=row.get("name"),
        image=row.get("image"),
        role=row.get("role") or "user",
        banned=bool(row.get("banned")),
        ban_reason=row.get("ban_reason"),
        ban_expires_at=row.get("ban_expires_at"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _session_out(row: Mapping[str, Any]) -> AdminSessionOut:
    return AdminSessionOut(
        id=row["id"],
        user_id=row["user_id"],
        expires_at=row["expires_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        ip_address=row.get("ip_address"),
        user_agent=row.get("user_agent"),
        impersonated_by=row.get("impersonated_by"),
    )


def _banned_now(
    banned: Any, expires_at: datetime | None, now: datetime
) -> bool:  # Any: a stored flag, possibly NULL
    """A ban counts until ``ban_expires_at``; an expired one is no ban."""
    return bool(banned) and (expires_at is None or now < expires_at)


def _row_banned(row: Mapping[str, Any], now: datetime) -> bool:
    return _banned_now(row.get("banned"), row.get("ban_expires_at"), now)


def admin(
    *,
    admin_roles: tuple[str, ...] = ("admin",),
    admin_user_ids: tuple[str, ...] = (),
    impersonation_expires_in: Duration = "1h",
    allow_impersonating_admins: bool = False,
    impersonation_blocked: tuple[str, ...] = IMPERSONATION_BLOCKED,
) -> Plugin:
    """Return the ``admin`` plugin: find, create, ban and remove users, set their roles
    and passwords, manage their sessions and impersonate them.

    Every endpoint needs a session (not an API key or OAuth token) of a user whose
    ``role`` is in ``admin_roles`` or whose id is in ``admin_user_ids``, and that is not
    itself an impersonation.

    Args:
        admin_roles: Roles that make a user an admin.
        admin_user_ids: Users who are admins whatever their role.
        impersonation_expires_in: How long an impersonation session lasts. It never
            slides past this.
        allow_impersonating_admins: Let admins impersonate other admins.
        impersonation_blocked: Endpoint ids an impersonation session may not call:
            by default those that create credentials outliving it (API keys, agents,
            OAuth grants) and the account's security settings.

    Returns:
        The plugin.

    Raises:
        ConfigError: No way to be an admin, or a zero impersonation lifetime.
    """
    if not admin_roles and not admin_user_ids:
        msg = "admin() needs admin_roles or admin_user_ids"
        raise ConfigError(msg)
    impersonation_ttl = to_timedelta(impersonation_expires_in)
    if impersonation_ttl <= timedelta(0):
        msg = "admin(impersonation_expires_in=...) must be positive"
        raise ConfigError(msg)
    roles = frozenset(admin_roles)
    user_ids = frozenset(admin_user_ids)
    states: weakref.WeakKeyDictionary[Any, _State] = weakref.WeakKeyDictionary()

    def state(ctx: EndpointContext) -> _State:
        found = states.get(ctx.auth)
        if found is None:
            found = states[ctx.auth] = _State()
        return found

    def is_admin(row: Mapping[str, Any]) -> bool:
        return row["id"] in user_ids or (row.get("role") or "user") in roles

    # ------------------------------------------------------------ bans

    async def clear_expired_ban(
        ctx: EndpointContext, user_id: str, expires_at: datetime
    ) -> None:
        # Compare-and-set: a new ban written meanwhile is kept.
        await ctx.adapter.update(
            "user",
            [
                Where("id", user_id),
                Where("banned", True),
                Where("ban_expires_at", expires_at),
            ],
            {
                "banned": False,
                "ban_reason": None,
                "ban_expires_at": None,
                "updated_at": ctx.clock.now(),
            },
        )
        state(ctx).bans.pop(user_id)

    async def check_ban(ctx: EndpointContext, row: Mapping[str, Any]) -> None:
        """Raise ADMIN_USER_BANNED for a banned row; clear a ban that has expired."""
        now = ctx.clock.now()
        if _row_banned(row, now):
            raise _error("ADMIN_USER_BANNED")
        if row.get("banned"):
            await clear_expired_ban(ctx, row["id"], row["ban_expires_at"])

    async def check_ban_cached(ctx: EndpointContext, user_id: str) -> None:
        """Raise ADMIN_USER_BANNED for a banned user. Reads only: an expired ban
        counts as none here, and is cleared at the next sign-in."""
        bans = state(ctx).bans
        now = ctx.clock.now()
        entry = bans.get(user_id)
        if entry is None or not entry[2] <= now < entry[2] + BAN_CACHE_TTL:
            row = await ctx.adapter.find_one("user", [Where("id", user_id)])
            if row is None:
                return  # the credential's own lookup fails for a deleted user
            entry = (bool(row.get("banned")), row.get("ban_expires_at"), now)
            bans.put(user_id, entry)
        if _banned_now(entry[0], entry[1], now):
            raise _error("ADMIN_USER_BANNED")

    # ------------------------------------------------------------ impersonation

    async def impersonation(
        ctx: EndpointContext, session_id: str
    ) -> tuple[str, datetime] | Gone | None:
        """``(admin id, created_at)`` of an impersonation session, None for another
        session, ``"gone"`` for an unknown session whose row no longer exists."""
        cache = state(ctx).impersonations
        if session_id in cache:
            return cache.get(session_id)
        row = await ctx.adapter.find_one("session", [Where("id", session_id)])
        if row is None:
            return "gone"
        admin_id = row.get("impersonated_by")
        info = (admin_id, row["created_at"]) if admin_id else None
        cache.put(session_id, info)
        return info

    async def still_admin(ctx: EndpointContext, admin_id: str) -> bool:
        row = await ctx.adapter.find_one("user", [Where("id", admin_id)])
        return (
            row is not None and is_admin(row) and not _row_banned(row, ctx.clock.now())
        )

    async def end_impersonations_by(ctx: EndpointContext, admin_id: str) -> None:
        rows = await ctx.adapter.find_many(
            "session", [Where("impersonated_by", admin_id)]
        )
        for row in rows:
            await ctx.sessions.revoke(ctx, row["id"])

    def cookie_named(ctx: EndpointContext, base: str) -> str:
        config = ctx.auth.config
        return cookie_name(
            base, base_url=config.base_url, prefix=config.advanced.cookie_prefix
        )

    def cookie(
        ctx: EndpointContext, base: str, value: str, max_age: int | None
    ) -> None:
        ctx.set_cookie(
            SetCookie(
                name=cookie_named(ctx, base),
                value=value,
                max_age=max_age,
                secure=secure_cookies(ctx.auth.config.base_url),
            )
        )

    def remaining(ctx: EndpointContext, row: Mapping[str, Any]) -> int | None:
        if not row.get("remember_me"):
            return None  # a browser-session cookie, as the session service sets it
        left = row["expires_at"] - ctx.clock.now()
        return max(0, int(left / timedelta(seconds=1)))

    async def admin_session(
        ctx: EndpointContext, admin_id: str | None = None
    ) -> tuple[str, dict[str, Any]] | None:
        """The live session the admin cookie holds: (token, row). With ``admin_id``,
        only a session of that admin who is still an admin counts."""
        raw = ctx.request.cookies.get(cookie_named(ctx, "admin_session"))
        token = ctx.crypto.unsign(raw, purpose="admin_session") if raw else None
        if token is None:
            return None
        token_hash = ctx.crypto.hash_token(token)
        row = await ctx.adapter.find_one("session", [Where("token_hash", token_hash)])
        if (
            row is None
            or not ctx.crypto.equal(row["token_hash"], token_hash)
            or row.get("impersonated_by")
            or ctx.clock.now() >= row["expires_at"]
        ):
            return None
        if admin_id is not None and (
            row["user_id"] != admin_id or not await still_admin(ctx, admin_id)
        ):
            return None
        return token, row

    # ------------------------------------------------------------ checks

    async def principal_check(ctx: EndpointContext, principal: Principal) -> None:
        if principal.via == "session":
            info = await impersonation(ctx, principal.credential_id)
            if isinstance(info, tuple):
                admin_id, created_at = info
                over = ctx.clock.now() >= created_at + impersonation_ttl
                if over or not await still_admin(ctx, admin_id):
                    # Like an expired session: deleted when it is next presented.
                    await ctx.sessions.revoke(ctx, principal.credential_id)
                    raise AuthError("UNAUTHENTICATED", 401)
        if principal.user_id is not None:
            await check_ban_cached(ctx, principal.user_id)

    async def sign_in_interceptor(
        ctx: EndpointContext, user: User, method: str
    ) -> None:
        del method  # every sign-in method is blocked the same way
        row = await ctx.adapter.find_one("user", [Where("id", user.id)])
        if row is not None:
            await check_ban(ctx, row)

    async def before_user_delete(
        ctx: EndpointContext | None, row: dict[str, Any]
    ) -> None:
        # Impersonations the deleted user started end with them; set_null alone
        # would turn them into ordinary sessions of the target.
        if ctx is not None:
            await end_impersonations_by(ctx, row["id"])

    async def block_while_impersonating(
        ctx: EndpointContext, payload: HookPayload
    ) -> None:
        del payload
        principal = ctx.principal
        if principal is None or principal.via != "session":
            return
        info = await impersonation(ctx, principal.credential_id)
        if info == "gone":
            raise AuthError("UNAUTHENTICATED", 401)
        if info is not None:
            raise _error("ADMIN_IMPERSONATION_BLOCKED")

    async def before_sign_out(ctx: EndpointContext, payload: HookPayload) -> None:
        """Signing out of an impersonation signs the browser out completely: the
        session of the admin in the admin cookie ends too."""
        del payload
        if cookie_named(ctx, "admin_session") not in ctx.request.cookies:
            return
        own = await admin_session(ctx)
        if own is not None:
            await ctx.sessions.revoke(ctx, own[1]["id"])
        cookie(ctx, "admin_session", "", 0)
        principal = ctx.principal
        if principal is not None and principal.via == "session":
            info = await impersonation(ctx, principal.credential_id)
            if isinstance(info, tuple):
                await ctx.emit(
                    "admin.impersonation_stopped",
                    admin_id=info[0],
                    target_id=principal.user_id,
                    session_id=principal.credential_id,
                )

    async def require_admin(ctx: EndpointContext) -> str:
        """The calling admin's id; FORBIDDEN for anyone else."""
        principal = ctx.principal
        if principal is None or principal.via != "session" or principal.user_id is None:
            raise AuthError("FORBIDDEN", 403)
        # Impersonations, and sessions only the cookie cache still knows, are refused.
        if await impersonation(ctx, principal.credential_id) is not None:
            raise AuthError("FORBIDDEN", 403)
        row = await ctx.adapter.find_one("user", [Where("id", principal.user_id)])
        if row is None or not is_admin(row):
            raise AuthError("FORBIDDEN", 403)
        return principal.user_id

    async def target(ctx: EndpointContext) -> dict[str, Any]:
        row = await ctx.adapter.find_one(
            "user", [Where("id", ctx.path_params["user_id"])]
        )
        if row is None:
            raise AuthError("NOT_FOUND", 404)
        return row

    async def check_password(ctx: EndpointContext, password: str, email: str) -> None:
        settings = ctx.auth.config.email_password
        if len(password) < settings.min_password_length:
            raise AuthError("PASSWORD_TOO_SHORT", 400)
        if len(password) > settings.max_password_length:
            raise AuthError("PASSWORD_TOO_LONG", 400)
        if settings.password_check is not None:
            reason = await settings.password_check(password, email)
            if reason is not None:
                raise AuthError("PASSWORD_REJECTED", 400, reason or None)

    async def set_password(
        ctx: EndpointContext, user_id: str, password_hash: str
    ) -> None:
        now = ctx.clock.now()
        updated = await ctx.adapter.update(
            "account",
            [Where("user_id", user_id), Where("provider_id", CREDENTIAL_PROVIDER)],
            {"password_hash": password_hash, "updated_at": now},
        )
        if updated is None:
            await ctx.adapter.create(
                "account",
                {
                    "id": ctx.ids.new("acc"),
                    "user_id": user_id,
                    "provider_id": CREDENTIAL_PROVIDER,
                    "account_id": user_id,
                    "password_hash": password_hash,
                    "created_at": now,
                    "updated_at": now,
                },
            )

    def current_session(ctx: EndpointContext) -> str | None:
        principal = ctx.principal
        return principal.credential_id if principal is not None else None

    # ------------------------------------------------------------ users

    async def list_users(ctx: EndpointContext, body: ListUsersIn) -> UserListOut:
        await require_admin(ctx)
        where: list[Where] = []
        term = (body.search or "").strip()
        if term:
            where = [
                Where("email", term.lower(), op="contains"),
                Where("name", term, op="contains", connector="or"),
            ]
        total = await ctx.adapter.count("user", where)
        # Ties break by id (CCR 013), so pages never overlap.
        rows = await ctx.adapter.find_many(
            "user",
            where,
            limit=body.limit,
            offset=body.offset,
            sort_by=SortBy(body.sort_by, body.sort_direction),
        )
        return UserListOut(users=[_user_out(row) for row in rows], total=total)

    async def get_user(ctx: EndpointContext, _: None) -> AdminUserOut:
        await require_admin(ctx)
        return _user_out(await target(ctx))

    async def create_user(ctx: EndpointContext, body: CreateUserIn) -> AdminUserOut:
        await require_admin(ctx)
        if await ctx.adapter.find_one("user", [Where("email", body.email)]):
            raise AuthError("USER_ALREADY_EXISTS", 409)
        password_hash: str | None = None
        if body.password is not None:
            await check_password(ctx, body.password, body.email)
            password_hash = await ctx.crypto.hash_password(body.password)
        try:
            user = await ctx.auth.create_user_record(
                ctx,
                {
                    "email": body.email,
                    "name": body.name,
                    "email_verified": body.email_verified,
                    "role": body.role,
                    "banned": False,
                },
            )
        except UniqueViolation as exc:
            raise AuthError("USER_ALREADY_EXISTS", 409) from exc
        if password_hash is not None:
            await set_password(ctx, user.id, password_hash)
        return _user_out({**user.model_dump(), "role": body.role, "banned": False})

    async def remove_user(ctx: EndpointContext, _: None) -> StatusOut:
        admin_id = await require_admin(ctx)
        user_id = ctx.path_params["user_id"]
        if user_id == admin_id:
            raise _error("ADMIN_CANNOT_TARGET_SELF")
        # The only way to delete a user: config and plugin user hooks run, and
        # user.deleted is emitted (CONTRACTS 13).
        await ctx.auth.delete_user(ctx, user_id)
        state(ctx).bans.pop(user_id)
        return StatusOut(status="ok")

    async def set_user_role(ctx: EndpointContext, body: SetUserRoleIn) -> AdminUserOut:
        await require_admin(ctx)
        row = await target(ctx)
        previous = row.get("role") or "user"
        if previous == body.role:
            return _user_out(row)
        updated = await ctx.adapter.update(
            "user",
            [Where("id", row["id"])],
            {"role": body.role, "updated_at": ctx.clock.now()},
        )
        if updated is None:
            raise AuthError("NOT_FOUND", 404)
        if not is_admin(updated):
            await end_impersonations_by(ctx, row["id"])
        await ctx.emit(
            "user.role_changed",
            user_id=row["id"],
            role=body.role,
            previous_role=previous,
        )
        return _user_out(updated)

    async def set_user_password(
        ctx: EndpointContext, body: SetUserPasswordIn
    ) -> StatusOut:
        await require_admin(ctx)
        row = await target(ctx)
        await check_password(ctx, body.new_password, row["email"])
        await set_password(
            ctx, row["id"], await ctx.crypto.hash_password(body.new_password)
        )
        await ctx.sessions.revoke_all(
            ctx, row["id"], except_session_id=current_session(ctx)
        )
        await ctx.emit("password.changed", user_id=row["id"])
        return StatusOut(status="ok")

    async def ban_user(ctx: EndpointContext, body: BanUserIn) -> AdminUserOut:
        admin_id = await require_admin(ctx)
        if ctx.path_params["user_id"] == admin_id:
            raise _error("ADMIN_CANNOT_TARGET_SELF")
        row = await target(ctx)
        now = ctx.clock.now()
        expires_at: datetime | None = None
        if body.expires_in is not None:
            try:
                length = to_timedelta(body.expires_in)
                expires_at = now + length
            except (ValueError, OverflowError) as exc:
                raise AuthError("INVALID_REQUEST", 400) from exc
            if length <= timedelta(0):
                raise AuthError("INVALID_REQUEST", 400)
        updated = await ctx.adapter.update(
            "user",
            [Where("id", row["id"])],
            {
                "banned": True,
                "ban_reason": body.reason,
                "ban_expires_at": expires_at,
                "updated_at": now,
            },
        )
        if updated is None:
            raise AuthError("NOT_FOUND", 404)
        state(ctx).bans.pop(row["id"])
        await ctx.sessions.revoke_all(ctx, row["id"])
        await end_impersonations_by(ctx, row["id"])
        await ctx.emit(
            "user.banned",
            user_id=row["id"],
            reason=body.reason,
            expires_at=expires_at.isoformat() if expires_at is not None else None,
        )
        return _user_out(updated)

    async def unban_user(ctx: EndpointContext, _: None) -> AdminUserOut:
        await require_admin(ctx)
        row = await target(ctx)
        if not row.get("banned"):
            return _user_out(row)
        updated = await ctx.adapter.update(
            "user",
            [Where("id", row["id"])],
            {
                "banned": False,
                "ban_reason": None,
                "ban_expires_at": None,
                "updated_at": ctx.clock.now(),
            },
        )
        if updated is None:
            raise AuthError("NOT_FOUND", 404)
        state(ctx).bans.pop(row["id"])
        await ctx.emit("user.unbanned", user_id=row["id"])
        return _user_out(updated)

    # ------------------------------------------------------------ sessions

    async def list_user_sessions(ctx: EndpointContext, _: None) -> AdminSessionListOut:
        await require_admin(ctx)
        row = await target(ctx)
        rows = await ctx.adapter.find_many(
            "session",
            [Where("user_id", row["id"])],
            sort_by=SortBy("created_at", "desc"),
        )
        return AdminSessionListOut(sessions=[_session_out(r) for r in rows])

    async def revoke_user_sessions(
        ctx: EndpointContext, body: RevokeUserSessionsIn
    ) -> RevokedOut:
        await require_admin(ctx)
        row = await target(ctx)
        if body.session_id is not None:
            session = await ctx.adapter.find_one(
                "session",
                [Where("id", body.session_id), Where("user_id", row["id"])],
            )
            if session is None:
                raise AuthError("NOT_FOUND", 404)
            revoked = await ctx.sessions.revoke(ctx, body.session_id)
            return RevokedOut(count=1 if revoked else 0)
        count = await ctx.sessions.revoke_all(
            ctx, row["id"], except_session_id=current_session(ctx)
        )
        return RevokedOut(count=count)

    async def impersonate_user(ctx: EndpointContext, _: None) -> ImpersonateOut:
        admin_id = await require_admin(ctx)
        if ctx.path_params["user_id"] == admin_id:
            raise _error("ADMIN_CANNOT_TARGET_SELF")
        row = await target(ctx)
        if is_admin(row) and not allow_impersonating_admins:
            raise _error("ADMIN_CANNOT_IMPERSONATE_ADMIN")
        if _row_banned(row, ctx.clock.now()):
            raise _error("ADMIN_USER_BANNED")
        # The admin's own session, kept in a signed cookie when the browser sent it.
        principal = ctx.principal
        own = (
            await ctx.adapter.find_one(
                "session", [Where("id", principal.credential_id)]
            )
            if principal is not None
            else None
        )
        token = ctx.request.cookies.get(cookie_named(ctx, "session_token"))
        from_cookie = (
            own is not None
            and token is not None
            and ctx.crypto.equal(ctx.crypto.hash_token(token), own["token_hash"])
        )
        created = await ctx.sessions.create(
            ctx,
            row["id"],
            remember_me=False,
            expires_in=impersonation_ttl,
            extra={"impersonated_by": admin_id},
        )
        if from_cookie and own is not None and token is not None:
            # Gone when the impersonation is: an admin who never stops it does not
            # leave a live session token in the browser for days.
            left = remaining(ctx, own)
            ttl = int(impersonation_ttl / timedelta(seconds=1))
            cookie(
                ctx,
                "admin_session",
                ctx.crypto.sign(token, purpose="admin_session"),
                ttl if left is None else min(left, ttl),
            )
        await ctx.emit(
            "admin.impersonation_started",
            admin_id=admin_id,
            target_id=row["id"],
            session_id=created.session.id,
        )
        session = await ctx.adapter.find_one(
            "session", [Where("id", created.session.id)]
        )
        if session is None:  # created in this transaction
            raise AuthError("INTERNAL_ERROR", 500)
        expose = not from_cookie or ctx.auth.config.sessions.expose_token
        return ImpersonateOut(
            user=_user_out(row),
            session=_session_out(session),
            token=created.token if expose else None,
        )

    async def stop_impersonating(ctx: EndpointContext, _: None) -> StopImpersonatingOut:
        principal = ctx.principal
        if principal is None or principal.via != "session":
            raise AuthError("UNAUTHENTICATED", 401)
        info = await impersonation(ctx, principal.credential_id)
        if info == "gone":
            raise AuthError("UNAUTHENTICATED", 401)
        if info is None:
            raise _error("ADMIN_NOT_IMPERSONATING")
        admin_id = info[0]
        await ctx.sessions.revoke(ctx, principal.credential_id)
        own = await admin_session(ctx, admin_id)
        if own is not None:
            cookie(ctx, "session_token", own[0], remaining(ctx, own[1]))
            # The cookie cache was bound to the impersonation token.
            cookie(ctx, "session_data", "", 0)
        else:
            ctx.sessions.clear_cookies(ctx)
        cookie(ctx, "admin_session", "", 0)
        await ctx.emit(
            "admin.impersonation_stopped",
            admin_id=admin_id,
            target_id=principal.user_id,
            session_id=principal.credential_id,
        )
        return StopImpersonatingOut(restored=own is not None)

    # ------------------------------------------------------------ endpoints

    tags = ("admin",)

    def endpoint(
        id: str,
        method: str,
        path: str,
        handler: Any,  # Any: an endpoint handler
        **options: Any,  # Any: Endpoint options
    ) -> Endpoint[Any, Any]:
        options.setdefault("auth", "session")
        return Endpoint(id, method, path, handler, tags=tags, **options)  # type: ignore[arg-type]

    user_path = "/admin/users/{user_id}"
    endpoints = (
        endpoint(
            "list_users",
            "GET",
            "/admin/users",
            list_users,
            input=ListUsersIn,
            output=UserListOut,
            summary="Find users",
        ),
        endpoint(
            "create_user",
            "POST",
            "/admin/users",
            create_user,
            input=CreateUserIn,
            output=AdminUserOut,
            summary="Create a user",
        ),
        endpoint(
            "get_user",
            "GET",
            user_path,
            get_user,
            output=AdminUserOut,
            summary="Get a user",
        ),
        endpoint(
            "remove_user",
            "DELETE",
            user_path,
            remove_user,
            output=StatusOut,
            fresh_session=True,
            summary="Delete a user and everything they own",
        ),
        endpoint(
            "set_user_role",
            "POST",
            user_path + "/role",
            set_user_role,
            input=SetUserRoleIn,
            output=AdminUserOut,
            summary="Set a user's role",
        ),
        endpoint(
            "set_user_password",
            "POST",
            user_path + "/password",
            set_user_password,
            input=SetUserPasswordIn,
            output=StatusOut,
            fresh_session=True,
            summary="Set a user's password and sign them out",
        ),
        endpoint(
            "ban_user",
            "POST",
            user_path + "/ban",
            ban_user,
            input=BanUserIn,
            output=AdminUserOut,
            summary="Ban a user and sign them out",
        ),
        endpoint(
            "unban_user",
            "POST",
            user_path + "/unban",
            unban_user,
            output=AdminUserOut,
            summary="Lift a user's ban",
        ),
        endpoint(
            "list_user_sessions",
            "GET",
            user_path + "/sessions",
            list_user_sessions,
            output=AdminSessionListOut,
            summary="A user's sessions",
        ),
        endpoint(
            "revoke_user_sessions",
            "POST",
            user_path + "/sessions/revoke",
            revoke_user_sessions,
            input=RevokeUserSessionsIn,
            output=RevokedOut,
            summary="Revoke one or all of a user's sessions",
        ),
        endpoint(
            "impersonate_user",
            "POST",
            user_path + "/impersonate",
            impersonate_user,
            output=ImpersonateOut,
            fresh_session=True,
            summary="Sign in as a user for a while",
        ),
        endpoint(
            "stop_impersonating",
            "POST",
            "/admin/stop-impersonating",
            stop_impersonating,
            output=StopImpersonatingOut,
            summary="End an impersonation and return to the admin's session",
        ),
    )
    return Plugin(
        id="admin",
        schema={"user": USER_FIELDS, "session": SESSION_FIELDS},
        endpoints=endpoints,
        database_hooks=DatabaseHooks(
            hooks={"user": ModelHooks(before_delete=before_user_delete)}
        ),
        hooks=(
            Hook("before", tuple(impersonation_blocked), block_while_impersonating),
            Hook("before", ("sign_out",), before_sign_out),
        ),
        sign_in_interceptors=(sign_in_interceptor,),
        principal_checks=(principal_check,),
        error_codes=ERROR_CODES,
    )
