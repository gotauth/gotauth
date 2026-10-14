"""The ``two_factor`` plugin (work package P2): TOTP, single-use backup codes and an
optional email OTP fallback, required at every sign-in by a sign-in interceptor."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, TypeVar
from urllib.parse import quote, urlencode, urlsplit

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PydanticField

from gotauth.contracts.adapter import Where
from gotauth.contracts.core_schema import User
from gotauth.contracts.endpoints import (
    ChallengeState,
    Endpoint,
    EndpointContext,
    Plugin,
    SignInChallenge,
)
from gotauth.contracts.errors import AuthError
from gotauth.contracts.http import SetCookie
from gotauth.contracts.http_models import SignInOut, StatusOut
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.protection import RateLimitRule
from gotauth.contracts.schema import Field, ModelSchema, Reference, returned_only
from gotauth.contracts.sessions import cookie_name, secure_cookies

__all__ = ["TWO_FACTOR_MODEL", "two_factor"]

TWO_FACTOR_MODEL = ModelSchema(
    name="two_factor",
    fields=MappingProxyType(
        {
            "user_id": Field(
                "string",
                unique=True,
                references=Reference("user", on_delete="cascade"),
            ),
            # crypto.encrypt, purpose "two_factor_secret".
            "secret_enc": Field("text", returned=False),
            # hash_token("<user id>:<code>") of each unused backup code.
            "backup_code_hashes": Field("json", returned=False),
            "verified_at": Field("datetime", required=False),  # None: not confirmed
            "last_used_step": Field("integer", default=0),
            "version": Field("integer", default=0),  # compare-and-set counter
            "created_at": Field("datetime"),
        }
    ),
)
"""The ``two_factor`` model: one row per user, active once ``verified_at`` is set."""

USER_FIELDS = ModelSchema(
    name="user",
    fields=MappingProxyType(
        {"two_factor_enabled": Field("boolean", default=False, input=False)}
    ),
)

ERROR_CODES: dict[str, tuple[int, str]] = {
    "TWO_FACTOR_INVALID_CODE": (401, "The code is not valid"),
    "TWO_FACTOR_NOT_ENABLED": (400, "Two-factor authentication is not enabled"),
    "TWO_FACTOR_ALREADY_ENABLED": (409, "Two-factor authentication is already on"),
    "TWO_FACTOR_CONFLICT": (409, "Two-factor settings changed at the same time"),
}

OTP_TTL = to_timedelta("5m")
OTP_MAX_ATTEMPTS = 5
BACKUP_CODE_DIGITS = 10

Enforce = Callable[[User], bool | Awaitable[bool]]
T = TypeVar("T")


def _error(code: str) -> AuthError:
    status, message = ERROR_CODES[code]
    return AuthError(code, status, message)


# ---------------------------------------------------------------- models


class PasswordIn(BaseModel):
    """``{password?}``: needed for users who sign in with a password."""

    model_config = ConfigDict(extra="forbid")

    password: str | None = PydanticField(default=None, max_length=1024)


class EnableOut(BaseModel):
    """``enable_two_factor`` output, shown once."""

    totp_uri: str
    backup_codes: list[str]


class CodeIn(BaseModel):
    """A code, and whether to trust this device for 30 days."""

    model_config = ConfigDict(extra="forbid")

    code: str = PydanticField(min_length=1, max_length=64)
    trust_device: bool = False


class BackupCodesOut(BaseModel):
    """``regenerate_backup_codes`` output, shown once."""

    backup_codes: list[str]


# ---------------------------------------------------------------- settings


@dataclass(frozen=True)
class _Settings:
    issuer: str | None
    backup_code_count: int
    trust_device_max_age: Duration
    skip_for_methods: tuple[str, ...]
    email_otp: bool
    enforce: Enforce | None

    def methods(self) -> tuple[str, ...]:
        base = ("totp", "backup_code")
        return (*base, "email_otp") if self.email_otp else base

    async def enforced(self, user: User) -> bool:
        if self.enforce is None:
            return False
        result = self.enforce(user)
        if inspect.isawaitable(result):
            result = await result
        return bool(result)


def _issuer(ctx: EndpointContext, settings: _Settings) -> str:
    return settings.issuer or urlsplit(ctx.auth.config.base_url).hostname or "GotAuth"


def _cookie(ctx: EndpointContext, base: str) -> str:
    config = ctx.auth.config
    return cookie_name(
        base, base_url=config.base_url, prefix=config.advanced.cookie_prefix
    )


async def _row(ctx: EndpointContext, user_id: str) -> dict[str, Any] | None:  # Any: row
    return await ctx.adapter.find_one("two_factor", [Where("user_id", user_id)])


def _secret(ctx: EndpointContext, row: dict[str, Any]) -> str:  # Any: row
    secret = ctx.crypto.decrypt(row["secret_enc"], purpose="two_factor_secret")
    if secret is None:  # a rotated-out secret or a tampered row: fail closed
        raise AuthError("INTERNAL_ERROR", 500)
    return secret


def _backup_hash(ctx: EndpointContext, user_id: str, code: str) -> str:
    normalized = "".join(char for char in code if char.isalnum()).lower()
    return ctx.crypto.hash_token(f"{user_id}:{normalized}")


def _new_backup_codes(
    ctx: EndpointContext, user_id: str, count: int
) -> tuple[list[str], list[str]]:
    codes: list[str] = []
    for _ in range(count):
        digits = ctx.crypto.new_otp(BACKUP_CODE_DIGITS)
        codes.append(f"{digits[:5]}-{digits[5:]}")
    return codes, [_backup_hash(ctx, user_id, code) for code in codes]


def _session_user(ctx: EndpointContext) -> str | None:
    principal = ctx.principal
    if principal is None or principal.via != "session" or principal.user_id is None:
        return None
    return principal.user_id


async def _require_fresh(ctx: EndpointContext) -> str:
    """The session user, if the session is fresh (as ``fresh_session`` endpoints)."""
    user_id = _session_user(ctx)
    principal = ctx.principal
    if user_id is None or principal is None:
        raise AuthError("UNAUTHENTICATED", 401)
    row = await ctx.adapter.find_one("session", [Where("id", principal.credential_id)])
    fresh_age = to_timedelta(ctx.auth.config.sessions.fresh_age)
    if row is None or ctx.clock.now() - row["created_at"] >= fresh_age:
        raise AuthError("FRESH_SESSION_REQUIRED", 403)
    return user_id


def _usable_challenge(ctx: EndpointContext) -> ChallengeState | None:
    """The pending sign-in challenge if it is valid and unexpired, else None (a stale
    cookie never stands in the way of a session)."""
    try:
        return _challenge(ctx)
    except AuthError:
        return None


def _user(ctx: EndpointContext, row: dict[str, Any]) -> User:  # Any: row
    """The user as the core builds it (returned fields only)."""
    return User.model_validate(returned_only(ctx.auth.schema["user"], row))


def _challenge(ctx: EndpointContext) -> ChallengeState | None:
    """The pending sign-in challenge. A cookie that is present but invalid or expired
    raises, as ``finish_challenge`` would."""
    if not ctx.request.cookies.get(_cookie(ctx, "challenge")):
        return None
    state = ctx.auth.read_challenge(ctx)
    if state is None:
        raise AuthError("TOKEN_INVALID", 400)
    if ctx.clock.now() >= state.exp:
        raise AuthError("TOKEN_EXPIRED", 400)
    return state


async def _check_password(
    ctx: EndpointContext, user_id: str, password: str | None
) -> None:
    """Users with a password confirm it; social-only users have none to give."""
    account = await ctx.adapter.find_one(
        "account", [Where("user_id", user_id), Where("provider_id", "credential")]
    )
    stored = account.get("password_hash") if account is not None else None
    if not stored:
        return
    check = await ctx.crypto.verify_password(password or "", stored)
    if not check.ok:
        raise AuthError("INVALID_CREDENTIALS", 401)


async def _use_totp(ctx: EndpointContext, row: dict[str, Any], code: str) -> None:
    """Accept a TOTP code once: its time step must be newer than the last one used,
    claimed with a compare-and-set so two requests cannot both use it."""
    step = ctx.crypto.verify_totp(_secret(ctx, row), code.strip(), at=ctx.clock.now())
    last = int(row.get("last_used_step") or 0)
    if step is None or step <= last:
        raise _error("TWO_FACTOR_INVALID_CODE")
    claimed = await ctx.adapter.update(
        "two_factor",
        [Where("id", row["id"]), Where("last_used_step", last)],
        {"last_used_step": step},
    )
    if claimed is None:
        raise _error("TWO_FACTOR_INVALID_CODE")


async def _use_backup_code(
    ctx: EndpointContext, row: dict[str, Any], code: str
) -> None:  # Any: row
    wanted = _backup_hash(ctx, row["user_id"], code)
    hashes: list[Any] = row.get("backup_code_hashes") or []  # Any: JSON
    stored = [str(item) for item in hashes]
    match = None
    for item in stored:  # every comparison runs, in constant time each
        if ctx.crypto.equal(item, wanted):
            match = item
    if match is None:
        raise _error("TWO_FACTOR_INVALID_CODE")
    claimed = await ctx.adapter.update(
        "two_factor",
        [Where("id", row["id"]), Where("version", row["version"])],
        {
            "backup_code_hashes": [item for item in stored if item != match],
            "version": row["version"] + 1,
        },
    )
    if claimed is None:  # used concurrently
        raise _error("TWO_FACTOR_INVALID_CODE")


def two_factor(
    *,
    issuer: str | None = None,
    backup_code_count: int = 10,
    trust_device_max_age: Duration = "30d",
    skip_for_methods: Sequence[str] = ("passkey",),
    email_otp: bool = False,
    enforce: Enforce | None = None,
) -> Plugin:
    """Return the ``two_factor`` plugin.

    Args:
        issuer: The name authenticator apps show; default: the host of ``base_url``.
        backup_code_count: Single-use backup codes per user.
        trust_device_max_age: How long "trust this device" skips the second step.
        skip_for_methods: Sign-in methods that need no second step (a passkey is
            already two factors).
        email_otp: Also accept a code sent by email (needs an email sender).
        enforce: ``enforce(user) -> bool``. When true, a user without two-factor must
            set it up during sign-in, and cannot turn it off.

    Returns:
        The plugin.
    """
    settings = _Settings(
        issuer=issuer,
        backup_code_count=backup_code_count,
        trust_device_max_age=trust_device_max_age,
        skip_for_methods=tuple(skip_for_methods),
        email_otp=email_otp,
        enforce=enforce,
    )
    trust_ttl = to_timedelta(trust_device_max_age)

    # -------------------------------------------------------- trusted devices

    def trust_device(ctx: EndpointContext, user_id: str, row_id: str) -> None:
        exp = int((ctx.clock.now() + trust_ttl).timestamp())
        ctx.set_cookie(
            SetCookie(
                name=_cookie(ctx, "two_factor_trust"),
                value=ctx.crypto.sign(
                    f"{user_id}.{row_id}.{exp}", purpose="trusted_device"
                ),
                max_age=int(trust_ttl.total_seconds()),
                secure=secure_cookies(ctx.auth.config.base_url),
            )
        )

    def trusted(ctx: EndpointContext, user_id: str, row_id: str) -> bool:
        signed = ctx.request.cookies.get(_cookie(ctx, "two_factor_trust"))
        value = ctx.crypto.unsign(signed, purpose="trusted_device") if signed else None
        if value is None:
            return False
        parts = value.split(".")
        if len(parts) != 3 or not parts[2].isdigit():
            return False
        # Bound to the row: turning two-factor off and on again drops the devices.
        return (
            parts[0] == user_id
            and parts[1] == row_id
            and ctx.clock.now().timestamp() < int(parts[2])
        )

    # -------------------------------------------------------- interceptor

    async def interceptor(
        ctx: EndpointContext, user: User, method: str
    ) -> SignInChallenge | None:
        if method in settings.skip_for_methods:
            return None
        row = await _row(ctx, user.id)
        if row is not None and row.get("verified_at") is not None:
            if trusted(ctx, user.id, row["id"]):
                return None
            return SignInChallenge(type="two_factor", methods=settings.methods())
        if await settings.enforced(user):
            return SignInChallenge(type="two_factor_setup", methods=("totp",))
        return None

    async def finish(
        ctx: EndpointContext,
        state: ChallengeState,
        satisfied: str,
        row: dict[str, Any],  # Any: row
        remember: bool,
    ) -> SignInOut:
        out = await ctx.auth.finish_challenge(ctx, satisfied=satisfied)
        if remember:
            trust_device(ctx, state.user_id, row["id"])
        return out

    def factor(ctx: EndpointContext, satisfied: str) -> ChallengeState:
        state = _challenge(ctx)
        if state is None:
            raise AuthError("TOKEN_INVALID", 400)
        if satisfied not in state.methods or state.type != "two_factor":
            raise AuthError("FORBIDDEN", 403)
        return state

    async def counted(
        ctx: EndpointContext, state: ChallengeState, check: Awaitable[T]
    ) -> T:
        """Run a code check; a wrong code emits ``sign_in.failed`` for the user."""
        try:
            return await check
        except AuthError as error:
            if error.code == "TWO_FACTOR_INVALID_CODE":
                await ctx.emit(
                    "sign_in.failed",
                    user_id=state.user_id,
                    method=state.method,
                    reason="invalid_second_factor",
                )
            raise

    async def active_row(
        ctx: EndpointContext, user_id: str
    ) -> dict[str, Any]:  # Any: row
        row = await _row(ctx, user_id)
        if row is None or row.get("verified_at") is None:
            raise _error("TWO_FACTOR_NOT_ENABLED")
        return row

    # -------------------------------------------------------- endpoints

    async def enable(ctx: EndpointContext, body: PasswordIn) -> EnableOut:
        state = _usable_challenge(ctx)
        if state is not None and state.type == "two_factor_setup":
            # Required setup during sign-in: the password was just checked.
            user_id = state.user_id
        else:
            if _session_user(ctx) is None:
                _challenge(ctx)  # a bad challenge cookie says why
                raise AuthError("UNAUTHENTICATED", 401)
            user_id = await _require_fresh(ctx)
            await _check_password(ctx, user_id, body.password)
        existing = await _row(ctx, user_id)
        if existing is not None and existing.get("verified_at") is not None:
            raise _error("TWO_FACTOR_ALREADY_ENABLED")
        if existing is not None:  # an unconfirmed setup: start again
            await ctx.adapter.delete("two_factor", [Where("id", existing["id"])])
        user = await ctx.adapter.find_one("user", [Where("id", user_id)])
        if user is None:
            raise AuthError("TOKEN_INVALID", 400)
        secret = ctx.crypto.new_totp_secret()
        codes, hashes = _new_backup_codes(ctx, user_id, settings.backup_code_count)
        await ctx.adapter.create(
            "two_factor",
            {
                "id": ctx.ids.new("tfa"),
                "user_id": user_id,
                "secret_enc": ctx.crypto.encrypt(secret, purpose="two_factor_secret"),
                "backup_code_hashes": hashes,
                "verified_at": None,
                "last_used_step": 0,
                "version": 0,
                "created_at": ctx.clock.now(),
            },
        )
        issuer_name = _issuer(ctx, settings)
        label = quote(f"{issuer_name}:{user['email']}", safe="")
        query = urlencode(
            {
                "secret": secret,
                "issuer": issuer_name,
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
            },
            quote_via=quote,
        )
        return EnableOut(totp_uri=f"otpauth://totp/{label}?{query}", backup_codes=codes)

    async def confirm(
        ctx: EndpointContext, user_id: str, body: CodeIn
    ) -> dict[str, Any]:  # Any: row
        """Check the first code of a setup and turn two-factor on."""
        row = await _row(ctx, user_id)
        if row is None:
            raise _error("TWO_FACTOR_NOT_ENABLED")
        if row.get("verified_at") is not None:
            raise _error("TWO_FACTOR_ALREADY_ENABLED")
        await _use_totp(ctx, row, body.code)
        row = (
            await ctx.adapter.update(
                "two_factor", [Where("id", row["id"])], {"verified_at": ctx.clock.now()}
            )
            or row
        )
        await ctx.adapter.update(
            "user",
            [Where("id", user_id)],
            {"two_factor_enabled": True, "updated_at": ctx.clock.now()},
        )
        await ctx.emit("two_factor.enabled", user_id=user_id)
        return row

    async def verify_totp(ctx: EndpointContext, body: CodeIn) -> BaseModel:
        state = _usable_challenge(ctx)
        if state is not None:
            if "totp" not in state.methods:
                raise AuthError("FORBIDDEN", 403)
            if state.type == "two_factor_setup":
                row = await counted(ctx, state, confirm(ctx, state.user_id, body))
                return await finish(ctx, state, "totp", row, body.trust_device)
            if state.type != "two_factor":
                raise AuthError("FORBIDDEN", 403)
            row = await active_row(ctx, state.user_id)
            await counted(ctx, state, _use_totp(ctx, row, body.code))
            return await finish(ctx, state, "totp", row, body.trust_device)
        user_id = _session_user(ctx)
        if user_id is None:
            _challenge(ctx)  # a bad challenge cookie says why
            raise AuthError("UNAUTHENTICATED", 401)
        await confirm(ctx, user_id, body)
        return StatusOut(status="enabled")

    async def verify_backup_code(ctx: EndpointContext, body: CodeIn) -> SignInOut:
        state = factor(ctx, "backup_code")
        row = await active_row(ctx, state.user_id)
        await counted(ctx, state, _use_backup_code(ctx, row, body.code))
        return await finish(ctx, state, "backup_code", row, body.trust_device)

    async def disable(ctx: EndpointContext, body: PasswordIn) -> StatusOut:
        user_id = _session_user(ctx) or ""  # session and freshness: the endpoint
        await _check_password(ctx, user_id, body.password)
        row = await _row(ctx, user_id)
        if row is None:
            raise _error("TWO_FACTOR_NOT_ENABLED")
        user_row = await ctx.adapter.find_one("user", [Where("id", user_id)])
        if user_row is not None and await settings.enforced(_user(ctx, user_row)):
            raise AuthError("FORBIDDEN", 403, "Two-factor is required for this account")
        await ctx.adapter.delete("two_factor", [Where("id", row["id"])])
        await ctx.adapter.update(
            "user",
            [Where("id", user_id)],
            {"two_factor_enabled": False, "updated_at": ctx.clock.now()},
        )
        if row.get("verified_at") is not None:
            await ctx.emit("two_factor.disabled", user_id=user_id)
        return StatusOut(status="disabled")

    async def regenerate(ctx: EndpointContext, _: None) -> BackupCodesOut:
        user_id = _session_user(ctx) or ""  # session and freshness: the endpoint
        row = await active_row(ctx, user_id)
        codes, hashes = _new_backup_codes(ctx, user_id, settings.backup_code_count)
        claimed = await ctx.adapter.update(
            "two_factor",
            [Where("id", row["id"]), Where("version", row["version"])],
            {"backup_code_hashes": hashes, "version": row["version"] + 1},
        )
        if claimed is None:
            raise _error("TWO_FACTOR_CONFLICT")
        return BackupCodesOut(backup_codes=codes)

    def otp_identifier(user_id: str) -> str:
        return f"two_factor_otp:{user_id}"

    async def send_otp(ctx: EndpointContext, _: None) -> StatusOut:
        state = factor(ctx, "email_otp")
        user = await ctx.adapter.find_one("user", [Where("id", state.user_id)])
        if user is None:
            raise AuthError("TOKEN_INVALID", 400)
        identifier = otp_identifier(state.user_id)
        await ctx.adapter.delete("verification", [Where("identifier", identifier)])
        code = ctx.crypto.new_otp(6)
        now = ctx.clock.now()
        new_id = ctx.ids.new("ver")
        await ctx.adapter.create(
            "verification",
            {
                "id": new_id,
                "identifier": identifier,
                # Short codes: hashed with their identifier (CONTRACTS 2.1).
                "value_hash": ctx.crypto.hash_token(f"{identifier}:{code}"),
                "expires_at": now + OTP_TTL,
                "created_at": now,
                "attempts": 0,
            },
        )
        # One live code per user, also when two sends overlap.
        await ctx.adapter.delete(
            "verification",
            [Where("identifier", identifier), Where("id", new_id, "ne")],
        )
        await ctx.email.send("otp", user["email"], code=code)
        return StatusOut(status="sent")

    async def verify_otp(ctx: EndpointContext, body: CodeIn) -> SignInOut:
        state = factor(ctx, "email_otp")
        row = await active_row(ctx, state.user_id)
        identifier = otp_identifier(state.user_id)
        pending = await ctx.adapter.find_one(
            "verification", [Where("identifier", identifier)]
        )
        expected = ctx.crypto.hash_token(f"{identifier}:{body.code.strip()}")
        expired = pending is not None and ctx.clock.now() >= pending["expires_at"]
        if pending is None or expired:
            raise _error("TWO_FACTOR_INVALID_CODE")
        found = await ctx.adapter.find_one(
            "verification",
            [Where("identifier", identifier), Where("value_hash", expected)],
        )
        if found is None:
            pending_id = pending["id"]
            attempts = int(pending.get("attempts") or 0)

            async def count(later: EndpointContext) -> None:
                # After the rollback, in its own transaction (CCR 012).
                if attempts + 1 >= OTP_MAX_ATTEMPTS:
                    await later.adapter.delete(
                        "verification", [Where("id", pending_id)]
                    )
                    return
                counted_row = await later.adapter.update(
                    "verification",
                    [Where("id", pending_id), Where("attempts", attempts)],
                    {"attempts": attempts + 1},
                )
                if counted_row is None:  # a concurrent guess: fail closed
                    await later.adapter.delete(
                        "verification", [Where("id", pending_id)]
                    )

            ctx.on_failure(count)
            await ctx.emit(
                "sign_in.failed",
                user_id=state.user_id,
                method=state.method,
                reason="invalid_second_factor",
            )
            raise _error("TWO_FACTOR_INVALID_CODE")
        deleted = await ctx.adapter.delete("verification", [Where("id", found["id"])])
        if not deleted:  # used concurrently
            raise _error("TWO_FACTOR_INVALID_CODE")
        return await finish(ctx, state, "email_otp", row, body.trust_device)

    # -------------------------------------------------------- rate limits

    def verifier(ctx: EndpointContext, _: Any) -> str | None:  # Any: the input
        # Per user, across IPs: the challenge's user, else the session's.
        try:
            state = ctx.auth.read_challenge(ctx)
        except Exception:  # an unreadable cookie counts as none
            state = None
        if state is not None:
            return state.user_id
        principal = ctx.principal
        return principal.user_id if principal is not None else None

    tags = ("two-factor",)
    endpoints: list[Endpoint[Any, Any]] = [
        Endpoint(
            "enable_two_factor",
            "POST",
            "/two-factor/enable",
            enable,
            input=PasswordIn,
            output=EnableOut,
            auth="optional",
            summary="Start two-factor setup: an authenticator URI and backup codes",
            tags=tags,
        ),
        Endpoint(
            "verify_totp",
            "POST",
            "/two-factor/verify-totp",
            verify_totp,
            input=CodeIn,
            auth="optional",
            summary="Confirm setup, or answer the sign-in challenge, with a TOTP code",
            tags=tags,
        ),
        Endpoint(
            "verify_backup_code",
            "POST",
            "/two-factor/verify-backup-code",
            verify_backup_code,
            input=CodeIn,
            output=SignInOut,
            summary="Answer the sign-in challenge with a backup code",
            tags=tags,
        ),
        Endpoint(
            "disable_two_factor",
            "POST",
            "/two-factor/disable",
            disable,
            input=PasswordIn,
            output=StatusOut,
            auth="session",
            fresh_session=True,
            summary="Turn two-factor authentication off",
            tags=tags,
        ),
        Endpoint(
            "regenerate_backup_codes",
            "POST",
            "/two-factor/regenerate-backup-codes",
            regenerate,
            output=BackupCodesOut,
            auth="session",
            fresh_session=True,
            summary="Replace the backup codes (shown once)",
            tags=tags,
        ),
    ]
    if email_otp:
        endpoints += [
            Endpoint(
                "send_two_factor_otp",
                "POST",
                "/two-factor/send-otp",
                send_otp,
                output=StatusOut,
                summary="Email a one-time code for the sign-in challenge",
                tags=tags,
            ),
            Endpoint(
                "verify_two_factor_otp",
                "POST",
                "/two-factor/verify-otp",
                verify_otp,
                input=CodeIn,
                output=SignInOut,
                summary="Answer the sign-in challenge with the emailed code",
                tags=tags,
            ),
        ]
    return Plugin(
        id="two_factor",
        schema={"two_factor": TWO_FACTOR_MODEL, "user": USER_FIELDS},
        endpoints=tuple(endpoints),
        sign_in_interceptors=(interceptor,),
        error_codes=ERROR_CODES,
        rate_limits=(
            RateLimitRule(
                path="/two-factor/verify-*",
                window="15m",
                max=10,
                key="identifier",
                identifier=verifier,
            ),
            # Enable and disable check the password, send-otp sends email: capped
            # per user too, not only per IP.
            RateLimitRule(
                path="/two-factor/*",
                window="15m",
                max=20,
                key="identifier",
                identifier=verifier,
            ),
        ),
        requires_email=email_otp,
    )
