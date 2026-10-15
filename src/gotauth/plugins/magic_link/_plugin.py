"""Passwordless sign-in (work package P4): ``magic_link()`` by emailed link and
``email_otp()`` by emailed 6-digit code, which also verifies email addresses and
resets passwords. Both follow the enumeration rules of CONTRACTS 9.1."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Literal
from urllib.parse import urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

from gotauth.contracts.adapter import Where
from gotauth.contracts.core_schema import User
from gotauth.contracts.email import EmailKind
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError
from gotauth.contracts.http import AuthResponse
from gotauth.contracts.http_models import ChallengeOut, SignInOut, StatusOut
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.protection import validate_redirect
from gotauth.contracts.schema import returned_only

__all__ = ["email_otp", "magic_link"]

logger = logging.getLogger("gotauth.magic_link")

MAGIC_PREFIX = "gav_"
OTP_MAX_ATTEMPTS = 5
_NO_USER = "usr_" + "0" * 26
"""A user id no row has: the lookup for an unknown email (CONTRACTS 9.1)."""

OtpType = Literal["sign_in", "verify_email", "reset_password"]


# ---------------------------------------------------------------- shared helpers


def _email(value: str) -> str:
    email = value.strip().lower()
    if len(email) > 254 or "@" not in email or email.startswith("@"):
        raise ValueError("invalid email address")
    return email


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def _find_user(
    ctx: EndpointContext, email: str
) -> dict[str, Any] | None:  # Any: row
    return await ctx.adapter.find_one("user", [Where("email", email)])


def _user(ctx: EndpointContext, row: dict[str, Any]) -> User:  # Any: row
    return User.model_validate(returned_only(ctx.auth.schema["user"], row))


async def _send(ctx: EndpointContext, kind: EmailKind, to: str, **data: Any) -> None:
    """Send an email; a failure is logged by type and never changes the reply."""
    try:
        await ctx.email.send(kind, to, **data)
    except Exception as exc:
        logger.warning("gotauth: %s email failed (%s)", kind, type(exc).__name__)


async def _cooling_down(
    ctx: EndpointContext, identifier: str, cooldown: timedelta
) -> bool:
    """A code or link for this identifier was sent within the cooldown."""
    recent = await ctx.adapter.find_one(
        "verification",
        [
            Where("identifier", identifier),
            Where("created_at", ctx.clock.now() - cooldown, "gt"),
        ],
    )
    return recent is not None


async def _signed_in_user(
    ctx: EndpointContext, row: dict[str, Any] | None, email: str, allow_sign_up: bool
) -> User | None:  # Any: row
    """The user for a proven email: found (and marked verified), or created when
    sign-up is allowed. ``None`` when neither."""
    if row is None:
        if not allow_sign_up:
            return None
        return await ctx.auth.create_user_record(
            ctx, {"email": email, "email_verified": True}
        )
    if not row["email_verified"]:
        # The link or code went to this address, so its owner proved control of it.
        await _claim(ctx, row)
        row = (
            await ctx.adapter.update(
                "user",
                [Where("id", row["id"])],
                {"email_verified": True, "updated_at": ctx.clock.now()},
            )
            or row
        )
        await ctx.emit("user.email_verified", user_id=row["id"])
    return _user(ctx, row)


async def _claim(ctx: EndpointContext, row: dict[str, Any]) -> None:  # Any: row
    """Someone may have registered this address before its owner (pre-account
    hijacking): the password, passkeys, two-factor setup and sessions of an
    unverified account were set up without proof of the email, so they go before
    the owner signs in. The account's data and social logins stay."""
    user_id = row["id"]
    await ctx.adapter.delete(
        "account", [Where("user_id", user_id), Where("provider_id", "credential")]
    )
    schema = ctx.auth.schema
    if "passkey" in schema:
        await ctx.adapter.delete("passkey", [Where("user_id", user_id)])
    if "two_factor" in schema:
        await ctx.adapter.delete("two_factor", [Where("user_id", user_id)])
        if "two_factor_enabled" in schema["user"].fields:
            await ctx.adapter.update(
                "user", [Where("id", user_id)], {"two_factor_enabled": False}
            )
    await ctx.sessions.revoke_all(ctx, user_id)


def _with_query(url: str, **params: str) -> str:
    parts = urlsplit(url)
    query = f"{parts.query}&{urlencode(params)}" if parts.query else urlencode(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


# ---------------------------------------------------------------- magic link


class SendMagicLinkIn(_In):
    """``send_magic_link`` input."""

    email: str = Field(max_length=254)
    callback_url: str = "/"
    error_callback_url: str | None = None


class VerifyMagicLinkIn(BaseModel):
    """``verify_magic_link`` query; other parameters (click tracking) are ignored."""

    model_config = ConfigDict(extra="ignore")

    token: str = Field(min_length=1, max_length=256)


def magic_link(
    *,
    allow_sign_up: bool = True,
    expires_in: Duration = "10m",
    send_cooldown: Duration = "60s",
) -> Plugin:
    """Return the ``magic_link`` plugin: sign in by a link sent by email.

    Args:
        allow_sign_up: Create the account on first sign-in. When False, an unknown
            email gets no link (and the same answer).
        expires_in: How long a link works.
        send_cooldown: A repeat request inside it answers the same and sends nothing.

    Returns:
        The plugin. It needs an email sender.
    """
    ttl = to_timedelta(expires_in)
    cooldown = to_timedelta(send_cooldown)

    async def send(ctx: EndpointContext, body: SendMagicLinkIn) -> StatusOut:
        config = ctx.auth.config
        callback = validate_redirect(body.callback_url, config)
        error_callback = (
            validate_redirect(body.error_callback_url, config)
            if body.error_callback_url is not None
            else None
        )
        try:
            email = _email(body.email)
        except ValueError as exc:
            raise AuthError("INVALID_REQUEST", 400) from exc
        row = await _find_user(ctx, email)
        known = row is not None

        async def deliver(later: EndpointContext) -> None:
            identifier = f"magic_link:{email}"
            if not known and not allow_sign_up:
                await _find_user(later, email)  # the same work as a real send
                return
            if await _cooling_down(later, identifier, cooldown):
                return
            await later.adapter.delete(
                "verification", [Where("identifier", identifier)]
            )
            token = later.crypto.random_token(MAGIC_PREFIX)
            now = later.clock.now()
            new_id = later.ids.new("ver")
            await later.adapter.create(
                "verification",
                {
                    "id": new_id,
                    "identifier": identifier,
                    "value_hash": later.crypto.hash_token(token),
                    "expires_at": now + ttl,
                    "created_at": now,
                    "data": {
                        "callback_url": callback,
                        "error_callback_url": error_callback,
                    },
                },
            )
            # One live link per email, also when two sends overlap.
            await later.adapter.delete(
                "verification",
                [Where("identifier", identifier), Where("id", new_id, "ne")],
            )
            # A "/..." url is joined to base_url + base_path by the email service.
            url = f"/magic-link/verify?{urlencode({'token': token})}"
            await _send(later, "magic_link", email, url=url)

        # After the reply and for every email alike (CONTRACTS 9.1).
        ctx.defer(deliver)
        return StatusOut(status="ok")

    async def verify(ctx: EndpointContext, query: VerifyMagicLinkIn) -> AuthResponse:
        token_hash = ctx.crypto.hash_token(query.token)
        row = await ctx.adapter.find_one(
            "verification", [Where("value_hash", token_hash)]
        )
        if row is None or not str(row["identifier"]).startswith("magic_link:"):
            raise AuthError("TOKEN_INVALID", 400)
        data: dict[str, Any] = row.get("data") or {}  # Any: JSON
        error_callback = data.get("error_callback_url")

        def fail(code: str, status: int) -> AuthResponse:
            if error_callback:
                return AuthResponse(redirect=_with_query(error_callback, error=code))
            raise AuthError(code, status)

        if ctx.clock.now() >= row["expires_at"]:
            return fail("TOKEN_EXPIRED", 400)
        consumed = await ctx.adapter.delete(
            "verification",
            [
                Where("id", row["id"]),
                Where("value_hash", token_hash),
                Where("expires_at", ctx.clock.now(), "gt"),
            ],
        )
        if consumed != 1:  # used concurrently
            return fail("TOKEN_INVALID", 400)
        email = str(row["identifier"]).removeprefix("magic_link:")
        user = await _signed_in_user(
            ctx, await _find_user(ctx, email), email, allow_sign_up
        )
        if user is None:
            return fail("TOKEN_INVALID", 400)
        try:
            result = await ctx.auth.complete_sign_in(ctx, user, method="magic_link")
        except AuthError as error:  # e.g. a sign-in interceptor refused
            if not error_callback:
                raise
            return AuthResponse(redirect=_with_query(error_callback, error=error.code))
        callback = str(data.get("callback_url") or "/")
        if isinstance(result, ChallengeOut):
            callback = _with_query(callback, challenge=result.challenge.type)
        return AuthResponse(redirect=callback)

    return Plugin(
        id="magic_link",
        endpoints=(
            Endpoint(
                "send_magic_link",
                "POST",
                "/magic-link/send",
                send,
                input=SendMagicLinkIn,
                output=StatusOut,
                summary="Email a sign-in link (the same answer for every email)",
                tags=("magic-link",),
            ),
            Endpoint(
                "verify_magic_link",
                "GET",
                "/magic-link/verify",
                verify,
                input=VerifyMagicLinkIn,
                summary="Sign in from an emailed link, then redirect",
                tags=("magic-link",),
            ),
        ),
        requires_email=True,
    )


# ---------------------------------------------------------------- email OTP


class SendEmailOtpIn(_In):
    """``send_email_otp`` input."""

    email: str = Field(max_length=254)
    type: OtpType


class VerifyEmailOtpIn(_In):
    """``verify_email_otp`` input."""

    email: str = Field(max_length=254)
    otp: str = Field(min_length=1, max_length=16)
    type: OtpType
    new_password: str | None = Field(default=None, max_length=4096)


ERROR_CODES: dict[str, tuple[int, str]] = {
    "EMAIL_OTP_INVALID": (400, "The code is not valid"),
}


def email_otp(
    *,
    allow_sign_up: bool = True,
    expires_in: Duration = "5m",
    send_cooldown: Duration = "60s",
) -> Plugin:
    """Return the ``email_otp`` plugin: 6-digit codes by email to sign in, verify an
    email address or reset a password.

    Args:
        allow_sign_up: Create the account on first sign-in by code.
        expires_in: How long a code works.
        send_cooldown: A repeat request inside it answers the same and sends nothing.

    Returns:
        The plugin. It needs an email sender.
    """
    ttl = to_timedelta(expires_in)
    cooldown = to_timedelta(send_cooldown)

    def invalid() -> AuthError:
        status, message = ERROR_CODES["EMAIL_OTP_INVALID"]
        return AuthError("EMAIL_OTP_INVALID", status, message)

    def applies(
        kind: OtpType,
        row: dict[str, Any] | None,  # Any: row
        has_password: bool,
    ) -> bool:
        if kind == "sign_in":
            return row is not None or allow_sign_up
        if kind == "verify_email":
            return row is not None and not row["email_verified"]
        # As C2: a reset changes an existing password, never adds one.
        return row is not None and has_password

    async def password_account(
        ctx: EndpointContext,
        row: dict[str, Any] | None,  # Any: row
    ) -> dict[str, Any] | None:  # Any: row
        # The same lookup for an unknown email (CONTRACTS 9.1).
        return await ctx.adapter.find_one(
            "account",
            [
                Where("user_id", row["id"] if row is not None else _NO_USER),
                Where("provider_id", "credential"),
            ],
        )

    async def send(ctx: EndpointContext, body: SendEmailOtpIn) -> StatusOut:
        try:
            email = _email(body.email)
        except ValueError as exc:
            raise AuthError("INVALID_REQUEST", 400) from exc
        row = await _find_user(ctx, email)
        account = await password_account(ctx, row)
        wanted = applies(body.type, row, account is not None)

        async def deliver(later: EndpointContext) -> None:
            identifier = f"email_otp:{body.type}:{email}"
            if not wanted:
                await _find_user(later, email)  # the same work as a real send
                return
            if await _cooling_down(later, identifier, cooldown):
                return
            await later.adapter.delete(
                "verification", [Where("identifier", identifier)]
            )
            code = later.crypto.new_otp(6)
            now = later.clock.now()
            new_id = later.ids.new("ver")
            await later.adapter.create(
                "verification",
                {
                    "id": new_id,
                    "identifier": identifier,
                    # Short codes: hashed with their identifier (CONTRACTS 2.1).
                    "value_hash": later.crypto.hash_token(f"{identifier}:{code}"),
                    "expires_at": now + ttl,
                    "created_at": now,
                    "attempts": 0,
                },
            )
            # One live code per email and type, also when two sends overlap.
            await later.adapter.delete(
                "verification",
                [Where("identifier", identifier), Where("id", new_id, "ne")],
            )
            await _send(later, "otp", email, code=code, purpose=body.type)

        ctx.defer(deliver)
        return StatusOut(status="ok")

    async def verify(
        ctx: EndpointContext, body: VerifyEmailOtpIn
    ) -> SignInOut | ChallengeOut | StatusOut:
        try:
            email = _email(body.email)
        except ValueError as exc:
            raise invalid() from exc
        if body.type == "reset_password":
            check_password(ctx, body.new_password)  # before the code is used
        identifier = f"email_otp:{body.type}:{email}"
        pending = await ctx.adapter.find_one(
            "verification", [Where("identifier", identifier)]
        )
        expected = ctx.crypto.hash_token(f"{identifier}:{body.otp.strip()}")
        usable = pending is not None and ctx.clock.now() < pending["expires_at"]
        if (
            pending is None
            or not usable
            or not ctx.crypto.equal(str(pending.get("value_hash", "")), expected)
        ):
            # The same reads and the same counting transaction whether or not a code
            # (and so an account) exists: timing says nothing (CONTRACTS 9.1).
            row = await _find_user(ctx, email)
            await count_failure(ctx, pending if usable else None)
            if row is not None and body.type == "sign_in":
                await ctx.emit(
                    "sign_in.failed",
                    user_id=row["id"],
                    method="email_otp",
                    reason="invalid_code",
                )
            raise invalid()
        consumed = await ctx.adapter.delete(
            "verification",
            [Where("id", pending["id"]), Where("value_hash", expected)],
        )
        if consumed != 1:  # used concurrently
            raise invalid()
        row = await _find_user(ctx, email)
        if body.type == "sign_in":
            user = await _signed_in_user(ctx, row, email, allow_sign_up)
            if user is None:
                raise invalid()
            return await ctx.auth.complete_sign_in(ctx, user, method="email_otp")
        if row is None:
            raise invalid()
        if body.type == "reset_password" and await password_account(ctx, row) is None:
            raise invalid()
        if body.type == "verify_email":
            await _signed_in_user(ctx, row, email, allow_sign_up=False)
            return StatusOut(status="verified")
        await reset_password(ctx, row, body.new_password or "")
        return StatusOut(status="ok")

    async def count_failure(
        ctx: EndpointContext,
        pending: dict[str, Any] | None,  # Any: row
    ) -> None:
        """Count a wrong code after the rollback (CCR 012); the 5th deletes it.
        Without a code, the same update runs on an id no row has."""
        pending_id = pending["id"] if pending is not None else "ver_" + "0" * 26
        attempts = int(pending.get("attempts") or 0) if pending is not None else 0

        async def count(later: EndpointContext) -> None:
            if attempts + 1 >= OTP_MAX_ATTEMPTS:
                await later.adapter.delete("verification", [Where("id", pending_id)])
                return
            counted = await later.adapter.update(
                "verification",
                [Where("id", pending_id), Where("attempts", attempts)],
                {"attempts": attempts + 1},
            )
            if counted is None:  # a concurrent guess: fail closed
                await later.adapter.delete("verification", [Where("id", pending_id)])

        ctx.on_failure(count)

    def check_password(ctx: EndpointContext, password: str | None) -> None:
        settings = ctx.auth.config.email_password
        if password is None or len(password) < settings.min_password_length:
            raise AuthError("PASSWORD_TOO_SHORT", 400)
        if len(password) > settings.max_password_length:
            raise AuthError("PASSWORD_TOO_LONG", 400)

    async def reset_password(
        ctx: EndpointContext,
        row: dict[str, Any],
        password: str,  # Any: row
    ) -> None:
        settings = ctx.auth.config.email_password
        if settings.password_check is not None:
            message = await settings.password_check(password, row["email"])
            if message is not None:
                raise AuthError("PASSWORD_REJECTED", 400, message)
        # An unverified account loses what an unproven party set up first (_claim),
        # then gets the password its proven owner just chose.
        await _signed_in_user(ctx, row, row["email"], allow_sign_up=False)
        password_hash = await ctx.crypto.hash_password(password)
        now = ctx.clock.now()
        account = await ctx.adapter.find_one(
            "account", [Where("user_id", row["id"]), Where("provider_id", "credential")]
        )
        if account is None:
            await ctx.adapter.create(
                "account",
                {
                    "id": ctx.ids.new("acc"),
                    "user_id": row["id"],
                    "provider_id": "credential",
                    "account_id": row["id"],
                    "password_hash": password_hash,
                    "created_at": now,
                    "updated_at": now,
                },
            )
        else:
            await ctx.adapter.update(
                "account",
                [Where("id", account["id"])],
                {"password_hash": password_hash, "updated_at": now},
            )
        if settings.revoke_sessions_on_password_reset:
            await ctx.sessions.revoke_all(ctx, row["id"])
        # Reset links from email + password (C2's "reset_password:<user id>") would
        # set the password again later: they go.
        await ctx.adapter.delete(
            "verification", [Where("identifier", f"reset_password:{row['id']}")]
        )
        await _send(
            ctx,
            "security_notice",
            row["email"],
            event="password.reset",
            at=ctx.clock.now().isoformat(),
            ip_address=ctx.request.client_ip,
        )
        await ctx.emit("password.reset", user_id=row["id"])

    return Plugin(
        id="email_otp",
        endpoints=(
            Endpoint(
                "send_email_otp",
                "POST",
                "/email-otp/send",
                send,
                input=SendEmailOtpIn,
                output=StatusOut,
                summary="Email a 6-digit code (the same answer for every email)",
                tags=("email-otp",),
            ),
            Endpoint(
                "verify_email_otp",
                "POST",
                "/email-otp/verify",
                verify,
                input=VerifyEmailOtpIn,
                summary="Sign in, verify an email or reset a password with a code",
                tags=("email-otp",),
            ),
        ),
        error_codes=ERROR_CODES,
        requires_email=True,
    )
