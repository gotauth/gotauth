"""The ``email_password`` plugin: sign-up, sign-in and account management (C2)."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from gotauth.contracts.adapter import Where
from gotauth.contracts.config import EmailPasswordConfig, ResolvedConfig
from gotauth.contracts.core_schema import User
from gotauth.contracts.email import EmailKind
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError, UniqueViolation
from gotauth.contracts.http import AuthResponse
from gotauth.contracts.http_models import ChallengeOut, SignInOut, StatusOut, UserOut
from gotauth.contracts.primitives import to_timedelta
from gotauth.contracts.principal import Principal
from gotauth.contracts.protection import validate_redirect
from gotauth.contracts.schema import returned_only

from ._models import (
    ChangeEmailIn,
    ChangePasswordIn,
    DeleteUserIn,
    RequestPasswordResetIn,
    ResetPasswordIn,
    SendVerificationEmailIn,
    SignInEmailIn,
    SignUpEmailIn,
    UpdateUserIn,
    VerifyEmailIn,
)
from ._tokens import consume_token, issue_token

__all__ = ["CREDENTIAL_PROVIDER", "email_password_plugin"]

CREDENTIAL_PROVIDER = "credential"
_logger = logging.getLogger("gotauth.email_password")


# ---------------------------------------------------------------- helpers


def _settings(ctx: EndpointContext) -> EmailPasswordConfig:
    return ctx.auth.config.email_password


def _check_length(ctx: EndpointContext, password: str) -> None:
    settings = _settings(ctx)
    if len(password) < settings.min_password_length:
        raise AuthError("PASSWORD_TOO_SHORT", 400)
    if len(password) > settings.max_password_length:
        raise AuthError("PASSWORD_TOO_LONG", 400)


def _redirect(ctx: EndpointContext, url: str | None) -> str | None:
    return validate_redirect(url, ctx.auth.config) if url is not None else None


def _user(ctx: EndpointContext, row: dict[str, Any]) -> User:
    return User.model_validate(returned_only(ctx.auth.schema["user"], row))


async def _find_user(ctx: EndpointContext, email: str) -> dict[str, Any] | None:
    return await ctx.adapter.find_one("user", [Where("email", email)])


async def _user_by_id(ctx: EndpointContext, user_id: str) -> dict[str, Any] | None:
    return await ctx.adapter.find_one("user", [Where("id", user_id)])


async def _credential(ctx: EndpointContext, user_id: str) -> dict[str, Any] | None:
    return await ctx.adapter.find_one(
        "account",
        [Where("user_id", user_id), Where("provider_id", CREDENTIAL_PROVIDER)],
    )


def _session_user(ctx: EndpointContext) -> Principal:
    principal = ctx.principal
    if principal is None or principal.user_id is None:  # the pipeline already checked
        raise AuthError("UNAUTHENTICATED", 401)
    return principal


async def _send(ctx: EndpointContext, kind: EmailKind, to: str, **data: Any) -> None:
    """Send an email; failures are logged without details and never change the reply."""
    try:
        await ctx.email.send(kind, to, **data)
    except Exception as exc:
        # Only the kind and exception type: messages and data can contain tokens.
        _logger.warning("gotauth: %s email failed (%s)", kind, type(exc).__name__)


_NO_USER = "usr_" + "0" * 26
"""A user id no row has: the lookup for an unknown email (CONTRACTS 9.1)."""


async def _send_verification(
    ctx: EndpointContext, user_id: str, email: str, callback_url: str | None
) -> None:
    token = await issue_token(
        ctx,
        "verify_email",
        user_id,
        _settings(ctx).verify_token_expires_in,
        {"email": email},
    )
    query = {"token": token}
    if callback_url is not None:
        query["callback_url"] = callback_url
    await _send(ctx, "verify_email", email, url=f"/verify-email?{urlencode(query)}")


async def _security_notice(ctx: EndpointContext, email: str, event: str) -> None:
    await _send(
        ctx,
        "security_notice",
        email,
        event=event,
        at=ctx.clock.now().isoformat(),
        ip_address=ctx.request.client_ip,
    )


def _with_query(url: str, **params: str) -> str:
    # Into the query, before any #fragment, so the app can read the values.
    parts = urlsplit(url)
    query = f"{parts.query}&{urlencode(params)}" if parts.query else urlencode(params)
    return urlunsplit(parts._replace(query=query))


async def _drop_tokens(ctx: EndpointContext, user_id: str, *kinds: str) -> None:
    """Delete a user's pending tokens of these kinds (old links stop working)."""
    for kind in kinds:
        await ctx.adapter.delete(
            "verification", [Where("identifier", f"{kind}:{user_id}")]
        )


# ---------------------------------------------------------------- sign-up and sign-in


async def _sign_up_email(
    ctx: EndpointContext, body: SignUpEmailIn
) -> SignInOut | ChallengeOut | StatusOut:
    settings = _settings(ctx)
    _check_length(ctx, body.password)
    callback_url = _redirect(ctx, body.callback_url)
    existing = await _find_user(ctx, body.email)
    if existing is not None and not await _release_abandoned(ctx, existing):
        return await _existing_sign_up(ctx, body, callback_url)
    password_hash = await ctx.crypto.hash_password(body.password)
    try:
        user = await ctx.auth.create_user_record(
            ctx, {"email": body.email, "name": body.name, "image": body.image}
        )
    except UniqueViolation:
        # A concurrent sign-up won; answer as for an existing email.
        return await _existing_sign_up(ctx, body, callback_url, hashed=True)
    now = ctx.clock.now()
    await ctx.adapter.create(
        "account",
        {
            "id": ctx.ids.new("acc"),
            "user_id": user.id,
            "provider_id": CREDENTIAL_PROVIDER,
            "account_id": user.id,
            "password_hash": password_hash,
            "created_at": now,
            "updated_at": now,
        },
    )
    if settings.require_email_verification:
        await _send_verification(ctx, user.id, user.email, callback_url)
        return StatusOut(status="verification_sent")
    if settings.auto_sign_in:
        return await ctx.auth.complete_sign_in(
            ctx, user, method="password", remember_me=body.remember_me
        )
    return StatusOut(status="ok")


async def _release_abandoned(ctx: EndpointContext, row: dict[str, Any]) -> bool:
    """Delete a sign-up nobody verified in time, so the email's owner can claim it.

    Someone else may have signed up with this address and a password they know
    (pre-account hijacking). Once the verification window has passed, the account is
    abandoned: it has never been verified and has no other sign-in method.
    """
    if row["email_verified"]:
        return False
    window = to_timedelta(_settings(ctx).verify_token_expires_in)
    if ctx.clock.now() - row["created_at"] < window:
        return False
    accounts = await ctx.adapter.find_many("account", [Where("user_id", row["id"])])
    if any(a["provider_id"] != CREDENTIAL_PROVIDER for a in accounts):
        return False
    await ctx.auth.delete_user(ctx, row["id"])
    return True


async def _existing_sign_up(
    ctx: EndpointContext,
    body: SignUpEmailIn,
    callback_url: str | None,
    *,
    hashed: bool = False,
) -> StatusOut:
    if not _settings(ctx).require_email_verification:
        raise AuthError("USER_ALREADY_EXISTS", 409)
    if not hashed:
        # Same work as a new sign-up, so timing does not reveal the account.
        await ctx.crypto.hash_password(body.password)
    url = callback_url or ctx.auth.config.base_url
    await _send(ctx, "sign_up_existing_account", body.email, url=_absolute(ctx, url))
    return StatusOut(status="verification_sent")


def _absolute(ctx: EndpointContext, url: str) -> str:
    return urljoin(ctx.auth.config.base_url, url)


async def _sign_in_email(
    ctx: EndpointContext, body: SignInEmailIn
) -> SignInOut | ChallengeOut:
    settings = _settings(ctx)

    async def fail(reason: str) -> AuthError:
        await ctx.emit("sign_in.failed", method="password", reason=reason)
        return AuthError("INVALID_CREDENTIALS", 401)

    if len(body.password) > settings.max_password_length:
        raise await fail("invalid_credentials")  # never hash an over-long input
    row = await _find_user(ctx, body.email)
    account = await _credential(ctx, row["id"]) if row is not None else None
    stored = account.get("password_hash") if account is not None else None
    # An empty hash runs a dummy verification, so unknown emails take as long.
    check = await ctx.crypto.verify_password(body.password, stored or "")
    if row is None or account is None or not stored or not check.ok:
        raise await fail("invalid_credentials")
    user = _user(ctx, row)
    if settings.require_email_verification and not user.email_verified:
        await ctx.emit("sign_in.failed", method="password", reason="email_not_verified")
        raise AuthError("EMAIL_NOT_VERIFIED", 403)
    if check.needs_rehash:
        new_hash = await ctx.crypto.hash_password(body.password)
        # Compare-and-set on the old hash: a concurrent change wins.
        await ctx.adapter.update(
            "account",
            [Where("id", account["id"]), Where("password_hash", stored)],
            {"password_hash": new_hash, "updated_at": ctx.clock.now()},
        )
    return await ctx.auth.complete_sign_in(
        ctx, user, method="password", remember_me=body.remember_me
    )


async def _sign_out(ctx: EndpointContext, _: None) -> StatusOut:
    principal = _session_user(ctx)
    if principal.via == "session":
        await ctx.sessions.revoke(ctx, principal.credential_id)
    ctx.sessions.clear_cookies(ctx)
    await ctx.emit("sign_out", user_id=principal.user_id)
    return StatusOut(status="ok")


# ---------------------------------------------------------------- verification


async def _send_verification_email(
    ctx: EndpointContext, body: SendVerificationEmailIn
) -> StatusOut:
    callback_url = _redirect(ctx, body.callback_url)
    row = await _find_user(ctx, body.email)
    target = (row["id"], row["email"]) if row and not row["email_verified"] else None

    async def send(later: EndpointContext) -> None:
        if target is None:
            await _credential(later, _NO_USER)  # same work as a real account
            return
        user_id, email = target
        # Only password users: a user created through a social provider that did
        # not verify the email was set up by whoever controls that provider
        # account, and the email's owner must not be able to verify it for them by
        # clicking a link.
        if await _credential(later, user_id) is not None:
            await _send_verification(later, user_id, email, callback_url)

    # After the reply, and for every email alike: work done only for existing
    # accounts must not show in the response time (CONTRACTS 9.1).
    ctx.defer(send)
    return StatusOut(status="ok")


async def _verify_email(
    ctx: EndpointContext, query: VerifyEmailIn
) -> StatusOut | AuthResponse:
    callback_url = _redirect(ctx, query.callback_url)
    try:
        await _apply_verification(ctx, query.token)
    except AuthError as error:
        if callback_url is None:
            raise
        return AuthResponse(redirect=_with_query(callback_url, error=error.code))
    if callback_url is not None:
        return AuthResponse(redirect=callback_url)
    return StatusOut(status="ok")


async def _apply_verification(ctx: EndpointContext, token: str) -> None:
    consumed = await consume_token(ctx, token, ("verify_email", "change_email"))
    row = await _user_by_id(ctx, consumed.user_id)
    if row is None:
        raise AuthError("TOKEN_INVALID", 400)
    now = ctx.clock.now()
    if consumed.kind == "verify_email":
        # The token verifies the address it was sent to, not a later one.
        if consumed.data.get("email") != row["email"]:
            raise AuthError("TOKEN_INVALID", 400)
        if await _credential(ctx, row["id"]) is None:
            raise AuthError("TOKEN_INVALID", 400)  # see _send_verification_email
        await ctx.adapter.update(
            "user",
            [Where("id", row["id"])],
            {"email_verified": True, "updated_at": now},
        )
        await ctx.emit("user.email_verified", user_id=row["id"])
        return
    new_email = consumed.data.get("new_email")
    if not isinstance(new_email, str):
        raise AuthError("TOKEN_INVALID", 400)
    taken = await _find_user(ctx, new_email)
    if taken is not None and taken["id"] != row["id"]:
        raise AuthError("USER_ALREADY_EXISTS", 409)
    try:
        await ctx.adapter.update(
            "user",
            [Where("id", row["id"])],
            {"email": new_email, "email_verified": True, "updated_at": now},
        )
    except UniqueViolation as exc:
        raise AuthError("USER_ALREADY_EXISTS", 409) from exc
    # Links sent to the old address must not outlive the change.
    await _drop_tokens(ctx, row["id"], "reset_password", "verify_email")
    await ctx.emit("user.email_changed", user_id=row["id"])


# ---------------------------------------------------------------- passwords


async def _request_password_reset(
    ctx: EndpointContext, body: RequestPasswordResetIn
) -> StatusOut:
    redirect_to = _absolute(ctx, validate_redirect(body.redirect_to, ctx.auth.config))
    row = await _find_user(ctx, body.email)
    target = (row["id"], row["email"]) if row else None

    async def send(later: EndpointContext) -> None:
        if target is None:
            await _credential(later, _NO_USER)  # same work as a real account
            return
        user_id, email = target
        if await _credential(later, user_id) is None:
            return
        token = await issue_token(
            later, "reset_password", user_id, _settings(later).reset_token_expires_in
        )
        await _send(
            later, "reset_password", email, url=_with_query(redirect_to, token=token)
        )

    # After the reply, and for every email alike: work done only for existing
    # accounts must not show in the response time (CONTRACTS 9.1).
    ctx.defer(send)
    return StatusOut(status="ok")


async def _reset_password(ctx: EndpointContext, body: ResetPasswordIn) -> StatusOut:
    _check_length(ctx, body.new_password)  # before consuming, so the token survives
    consumed = await consume_token(ctx, body.token, ("reset_password",))
    row = await _user_by_id(ctx, consumed.user_id)
    account = await _credential(ctx, consumed.user_id) if row is not None else None
    if row is None or account is None:
        raise AuthError("TOKEN_INVALID", 400)
    password_hash = await ctx.crypto.hash_password(body.new_password)
    now = ctx.clock.now()
    await ctx.adapter.update(
        "account",
        [Where("id", account["id"])],
        {"password_hash": password_hash, "updated_at": now},
    )
    if not row["email_verified"]:
        # The link went to this address, so its owner just proved control of it.
        await ctx.adapter.update(
            "user",
            [Where("id", row["id"])],
            {"email_verified": True, "updated_at": now},
        )
        await ctx.emit("user.email_verified", user_id=row["id"])
    if _settings(ctx).revoke_sessions_on_password_reset:
        await ctx.sessions.revoke_all(ctx, row["id"])
    await _security_notice(ctx, row["email"], "password.reset")
    await _drop_tokens(ctx, row["id"], "reset_password")
    await ctx.emit("password.reset", user_id=row["id"])
    return StatusOut(status="ok")


async def _change_password(ctx: EndpointContext, body: ChangePasswordIn) -> StatusOut:
    principal = _session_user(ctx)
    user_id = principal.user_id or ""
    _check_length(ctx, body.new_password)
    account = await _credential(ctx, user_id)
    stored = account.get("password_hash") if account is not None else None
    if len(body.current_password) > _settings(ctx).max_password_length:
        raise AuthError("INVALID_CREDENTIALS", 401)
    check = await ctx.crypto.verify_password(body.current_password, stored or "")
    if account is None or not stored or not check.ok:
        raise AuthError("INVALID_CREDENTIALS", 401)
    password_hash = await ctx.crypto.hash_password(body.new_password)
    await ctx.adapter.update(
        "account",
        [Where("id", account["id"])],
        {"password_hash": password_hash, "updated_at": ctx.clock.now()},
    )
    if body.revoke_other_sessions:
        keep = principal.credential_id if principal.via == "session" else None
        await ctx.sessions.revoke_all(ctx, user_id, except_session_id=keep)
    row = await _user_by_id(ctx, user_id)
    if row is not None:
        await _security_notice(ctx, row["email"], "password.changed")
    await _drop_tokens(ctx, user_id, "reset_password")
    await ctx.emit("password.changed", user_id=user_id)
    return StatusOut(status="ok")


# ---------------------------------------------------------------- account


async def _change_email(ctx: EndpointContext, body: ChangeEmailIn) -> StatusOut:
    principal = _session_user(ctx)
    callback_url = _redirect(ctx, body.callback_url)
    row = await _user_by_id(ctx, principal.user_id or "")
    if row is None:
        raise AuthError("UNAUTHENTICATED", 401)
    if body.new_email == row["email"]:
        return StatusOut(status="verification_sent")
    if await _find_user(ctx, body.new_email) is None:
        token = await issue_token(
            ctx,
            "change_email",
            row["id"],
            _settings(ctx).verify_token_expires_in,
            {"new_email": body.new_email},
        )
        query = {"token": token}
        if callback_url is not None:
            query["callback_url"] = callback_url
        await _send(
            ctx,
            "change_email",
            body.new_email,
            url=f"/verify-email?{urlencode(query)}",
            new_email=body.new_email,
        )
    # Same reply when the address is taken, so it does not reveal other accounts.
    await _security_notice(ctx, row["email"], "user.email_changed")
    return StatusOut(status="verification_sent")


async def _update_user(ctx: EndpointContext, body: UpdateUserIn) -> User:
    principal = _session_user(ctx)
    changes: dict[str, Any] = body.model_dump(exclude_unset=True)
    changes["updated_at"] = ctx.clock.now()
    row = await ctx.adapter.update("user", [Where("id", principal.user_id)], changes)
    if row is None:
        raise AuthError("UNAUTHENTICATED", 401)
    await ctx.emit("user.updated", user_id=principal.user_id)
    return _user(ctx, row)


async def _delete_user(ctx: EndpointContext, body: DeleteUserIn) -> StatusOut:
    principal = _session_user(ctx)
    user_id = principal.user_id or ""
    account = await _credential(ctx, user_id)
    stored = account.get("password_hash") if account is not None else None
    if stored:
        password = body.password or ""
        if not password or len(password) > _settings(ctx).max_password_length:
            raise AuthError("INVALID_CREDENTIALS", 401)
        if not (await ctx.crypto.verify_password(password, stored)).ok:
            raise AuthError("INVALID_CREDENTIALS", 401)
    await ctx.auth.delete_user(ctx, user_id)
    ctx.sessions.clear_cookies(ctx)
    return StatusOut(status="ok")


# ---------------------------------------------------------------- plugin


def email_password_plugin(
    config: EmailPasswordConfig | ResolvedConfig | None = None,
) -> Plugin:
    """Return the ``email_password`` plugin (CONTRACTS 13.2).

    ``config`` only decides ``requires_email``; every other setting is read from
    ``ctx.auth.config.email_password`` at request time.
    """
    if isinstance(config, ResolvedConfig):
        config = config.email_password
    settings = config or EmailPasswordConfig()
    tags = ("email_password",)
    return Plugin(
        id="email_password",
        requires_email=settings.require_email_verification,
        endpoints=(
            Endpoint(
                "sign_up_email",
                "POST",
                "/sign-up/email",
                _sign_up_email,
                input=SignUpEmailIn,
                output=SignInOut,
                summary="Sign up with email and password",
                tags=tags,
            ),
            Endpoint(
                "sign_in_email",
                "POST",
                "/sign-in/email",
                _sign_in_email,
                input=SignInEmailIn,
                output=SignInOut,
                summary="Sign in with email and password",
                tags=tags,
            ),
            Endpoint(
                "sign_out",
                "POST",
                "/sign-out",
                _sign_out,
                output=StatusOut,
                auth="session",
                summary="Sign out",
                tags=tags,
            ),
            Endpoint(
                "send_verification_email",
                "POST",
                "/send-verification-email",
                _send_verification_email,
                input=SendVerificationEmailIn,
                output=StatusOut,
                summary="Send the email verification link again",
                tags=tags,
            ),
            Endpoint(
                "verify_email",
                "GET",
                "/verify-email",
                _verify_email,
                input=VerifyEmailIn,
                output=StatusOut,
                summary="Verify an email address from a link",
                tags=tags,
            ),
            Endpoint(
                "request_password_reset",
                "POST",
                "/request-password-reset",
                _request_password_reset,
                input=RequestPasswordResetIn,
                output=StatusOut,
                summary="Email a password reset link",
                tags=tags,
            ),
            Endpoint(
                "reset_password",
                "POST",
                "/reset-password",
                _reset_password,
                input=ResetPasswordIn,
                output=StatusOut,
                summary="Set a new password with a reset token",
                tags=tags,
            ),
            Endpoint(
                "change_password",
                "POST",
                "/change-password",
                _change_password,
                input=ChangePasswordIn,
                output=StatusOut,
                auth="session",
                fresh_session=True,
                summary="Change your password",
                tags=tags,
            ),
            Endpoint(
                "change_email",
                "POST",
                "/change-email",
                _change_email,
                input=ChangeEmailIn,
                output=StatusOut,
                auth="session",
                fresh_session=True,
                summary="Change your email address",
                tags=tags,
            ),
            Endpoint(
                "update_user",
                "PATCH",
                "/user",
                _update_user,
                input=UpdateUserIn,
                output=UserOut,
                auth="session",
                summary="Update your profile",
                tags=tags,
            ),
            Endpoint(
                "delete_user",
                "DELETE",
                "/user",
                _delete_user,
                input=DeleteUserIn,
                input_format="json",
                output=StatusOut,
                auth="session",
                fresh_session=True,
                summary="Delete your account",
                tags=tags,
            ),
        ),
    )
