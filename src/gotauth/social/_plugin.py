"""The ``social`` plugin: sign-in and account linking with OAuth providers (C4)."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict

from gotauth.contracts.adapter import Where
from gotauth.contracts.core_schema import User
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError, UniqueViolation
from gotauth.contracts.http import AuthResponse, SetCookie
from gotauth.contracts.http_models import (
    AccountListOut,
    AccountOut,
    ChallengeOut,
    RedirectOut,
    StatusOut,
)
from gotauth.contracts.protection import validate_redirect
from gotauth.contracts.schema import returned_only
from gotauth.contracts.sessions import cookie_name, secure_cookies
from gotauth.contracts.social import OAuthProvider, ProviderTokens, ProviderUser

__all__ = [
    "CallbackIn",
    "LinkSocialIn",
    "SignInSocialIn",
    "UnlinkAccountIn",
    "social_plugin",
]

_logger = logging.getLogger("gotauth.social")
_STATE_TTL = 600  # seconds
_CREDENTIAL = "credential"


class SignInSocialIn(BaseModel):
    """``sign_in_social`` input."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    callback_url: str | None = None
    error_callback_url: str | None = None
    scopes: list[str] | None = None
    remember_me: bool = True


class LinkSocialIn(BaseModel):
    """``link_social`` input."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    callback_url: str | None = None
    scopes: list[str] | None = None


class CallbackIn(BaseModel):
    """Callback parameters; providers may add others, which are ignored."""

    model_config = ConfigDict(extra="ignore")

    code: str | None = None
    state: str | None = None
    error: str | None = None
    user: str | None = None  # Apple: name on the first sign-in


class UnlinkAccountIn(BaseModel):
    """``unlink_account`` input."""

    model_config = ConfigDict(extra="forbid")

    provider_id: str
    account_id: str | None = None


# ---------------------------------------------------------------- helpers


def _provider(ctx: EndpointContext, provider_id: str) -> OAuthProvider:
    provider = ctx.auth.providers.get(provider_id)
    if provider is None:
        raise AuthError("NOT_FOUND", 404, "Unknown provider")
    return provider


def _state_cookie(ctx: EndpointContext) -> str:
    config = ctx.auth.config
    return cookie_name(
        "oauth_state", base_url=config.base_url, prefix=config.advanced.cookie_prefix
    )


def _redirect_uri(ctx: EndpointContext, provider_id: str) -> str:
    config = ctx.auth.config
    return f"{config.base_url.rstrip('/')}{config.base_path}/callback/{provider_id}"


def _with_query(url: str, **params: str) -> str:
    parts = urlsplit(url)
    query = f"{parts.query}&{urlencode(params)}" if parts.query else urlencode(params)
    return urlunsplit(parts._replace(query=query))


def _principal_user(ctx: EndpointContext) -> str:
    principal = ctx.principal
    if principal is None or principal.user_id is None:  # the pipeline already checked
        raise AuthError("UNAUTHENTICATED", 401)
    return principal.user_id


async def _start(
    ctx: EndpointContext,
    provider: OAuthProvider,
    *,
    callback_url: str | None,
    error_callback_url: str | None,
    scopes: list[str] | None,
    remember_me: bool,
    link_user_id: str | None,
) -> RedirectOut:
    config = ctx.auth.config
    callback_url = validate_redirect(callback_url, config) if callback_url else None
    if error_callback_url:
        error_callback_url = validate_redirect(error_callback_url, config)
    wanted: list[str] = list(dict.fromkeys([*provider.default_scopes, *(scopes or [])]))
    state = ctx.crypto.random_token()
    verifier = ctx.crypto.random_token()
    nonce = ctx.crypto.random_token() if "openid" in wanted else None
    payload = {
        "verifier": verifier,
        "nonce": nonce,
        "callback_url": callback_url,
        "error_callback_url": error_callback_url,
        "link_user_id": link_user_id,
        "remember_me": remember_me,
    }
    now = ctx.clock.now()
    await ctx.adapter.create(
        "verification",
        {
            "id": ctx.ids.new("ver"),
            "identifier": f"oauth_state:{provider.id}",
            "value_hash": ctx.crypto.hash_token(state),
            "expires_at": now + timedelta(seconds=_STATE_TTL),
            "created_at": now,
            "data": {
                "sealed": ctx.crypto.encrypt(json.dumps(payload), purpose="oauth_state")
            },
        },
    )
    ctx.set_cookie(
        SetCookie(
            name=_state_cookie(ctx),
            value=ctx.crypto.sign(state, purpose="oauth_state"),
            max_age=_STATE_TTL,
            secure=secure_cookies(config.base_url),
            same_site="lax",
        )
    )
    prepare = getattr(provider, "prepare", None)
    if prepare is not None:
        await _guard(prepare(ctx.auth.http))
    url = provider.authorization_url(
        state=state,
        code_challenge=ctx.crypto.pkce_s256(verifier),
        redirect_uri=_redirect_uri(ctx, provider.id),
        scopes=wanted,
        nonce=nonce,
    )
    return RedirectOut(url=url)


async def _guard(awaitable: Any) -> Any:  # Any: any provider call
    """Run a provider call; anything but an AuthError becomes PROVIDER_ERROR."""
    try:
        return await awaitable
    except AuthError:
        raise
    except Exception as exc:
        _logger.warning("gotauth: provider call failed (%s)", type(exc).__name__)
        raise AuthError("PROVIDER_ERROR", 502) from exc


# ---------------------------------------------------------------- start endpoints


async def _sign_in_social(ctx: EndpointContext, body: SignInSocialIn) -> RedirectOut:
    return await _start(
        ctx,
        _provider(ctx, body.provider),
        callback_url=body.callback_url,
        error_callback_url=body.error_callback_url,
        scopes=body.scopes,
        remember_me=body.remember_me,
        link_user_id=None,
    )


async def _link_social(ctx: EndpointContext, body: LinkSocialIn) -> RedirectOut:
    return await _start(
        ctx,
        _provider(ctx, body.provider),
        callback_url=body.callback_url,
        error_callback_url=None,
        scopes=body.scopes,
        remember_me=True,
        link_user_id=_principal_user(ctx),
    )


# ---------------------------------------------------------------- callback


async def _consume_state(
    ctx: EndpointContext, provider: OAuthProvider, state: str | None
) -> dict[str, Any]:  # Any: the decrypted flow data
    """Check the state against the cookie and the database, and consume it once."""
    signed = ctx.request.cookies.get(_state_cookie(ctx))
    cookie_state = ctx.crypto.unsign(signed, purpose="oauth_state") if signed else None
    if not state or cookie_state is None or not ctx.crypto.equal(cookie_state, state):
        raise AuthError("TOKEN_INVALID", 400)
    value_hash = ctx.crypto.hash_token(state)
    row = await ctx.adapter.find_one("verification", [Where("value_hash", value_hash)])
    if row is None or row["identifier"] != f"oauth_state:{provider.id}":
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
        raise AuthError(
            "TOKEN_EXPIRED" if now >= row["expires_at"] else "TOKEN_INVALID", 400
        )
    stored: dict[str, Any] = row.get("data") or {}  # Any: JSON data
    sealed = stored.get("sealed")
    plain = (
        ctx.crypto.decrypt(sealed, purpose="oauth_state")
        if isinstance(sealed, str)
        else None
    )
    if plain is None:
        raise AuthError("TOKEN_INVALID", 400)
    data: dict[str, Any] = json.loads(plain)
    return data


async def _social_callback(ctx: EndpointContext, query: CallbackIn) -> AuthResponse:
    provider = _provider(ctx, ctx.path_params["provider"])
    flow = await _consume_state(ctx, provider, query.state)
    # The state is single use: clear its cookie whatever happens next.
    ctx.set_cookie(
        SetCookie(
            name=_state_cookie(ctx),
            value="",
            max_age=0,
            secure=secure_cookies(ctx.auth.config.base_url),
        )
    )
    callback_url: str | None = flow.get("callback_url")
    error_url: str | None = flow.get("error_callback_url") or callback_url
    try:
        target = await _finish(ctx, provider, query, flow)
    except AuthError as error:
        if error_url is None:
            raise
        return AuthResponse(redirect=_with_query(error_url, error=error.code))
    return AuthResponse(redirect=target or callback_url or "/")


async def _finish(
    ctx: EndpointContext,
    provider: OAuthProvider,
    query: CallbackIn,
    flow: dict[str, Any],  # Any: decrypted flow data
) -> str | None:
    """Exchange the code, then sign in or link. Returns a redirect override."""
    if query.error or not query.code:
        raise AuthError("PROVIDER_ERROR", 502, "The provider returned an error")
    redirect_uri = _redirect_uri(ctx, provider.id)
    tokens: ProviderTokens = await _guard(
        provider.exchange_code(
            ctx.auth.http,
            code=query.code,
            code_verifier=str(flow["verifier"]),
            redirect_uri=redirect_uri,
        )
    )
    profile: ProviderUser = await _guard(
        provider.get_user(ctx.auth.http, tokens, nonce=flow.get("nonce"))
    )
    name_from_form = getattr(provider, "name_from_form", None)
    if profile.name is None and name_from_form is not None:
        name = name_from_form(query.user)
        if name:
            profile = ProviderUser(
                id=profile.id,
                email=profile.email,
                email_verified=profile.email_verified,
                name=name,
                image=profile.image,
                raw=profile.raw,
            )
    link_user_id = flow.get("link_user_id")
    if isinstance(link_user_id, str):
        await _link(ctx, provider, profile, tokens, link_user_id)
        return None
    user = await _resolve_user(ctx, provider, profile, tokens)
    result = await ctx.auth.complete_sign_in(
        ctx, user, method="social", remember_me=bool(flow.get("remember_me", True))
    )
    if isinstance(result, ChallengeOut):
        target = flow.get("callback_url") or "/"
        return _with_query(target, challenge=result.challenge.type)
    return None


# ---------------------------------------------------------------- linking


def _token_fields(
    ctx: EndpointContext, provider: OAuthProvider, tokens: ProviderTokens
) -> dict[str, Any]:  # Any: account field values
    if not provider.store_provider_tokens:
        return {"scope": tokens.scope}

    def seal(value: str | None) -> str | None:
        return ctx.crypto.encrypt(value, purpose="account_token") if value else None

    return {
        "access_token_enc": seal(tokens.access_token),
        "refresh_token_enc": seal(tokens.refresh_token),
        "id_token_enc": seal(tokens.id_token),
        "access_token_expires_at": tokens.expires_at,
        "scope": tokens.scope,
    }


async def _find_pair(
    ctx: EndpointContext, provider: OAuthProvider, profile: ProviderUser
) -> dict[str, Any] | None:
    return await ctx.adapter.find_one(
        "account",
        [Where("provider_id", provider.id), Where("account_id", profile.id)],
    )


async def _add_account(
    ctx: EndpointContext,
    provider: OAuthProvider,
    profile: ProviderUser,
    tokens: ProviderTokens,
    user_id: str,
) -> None:
    now = ctx.clock.now()
    await ctx.adapter.create(
        "account",
        {
            "id": ctx.ids.new("acc"),
            "user_id": user_id,
            "provider_id": provider.id,
            "account_id": profile.id,
            "created_at": now,
            "updated_at": now,
            **_token_fields(ctx, provider, tokens),
        },
    )
    await ctx.emit("account.linked", user_id=user_id, provider_id=provider.id)


async def _user(ctx: EndpointContext, user_id: str) -> User:
    row = await ctx.adapter.find_one("user", [Where("id", user_id)])
    if row is None:
        raise AuthError("ACCOUNT_NOT_LINKED", 409)
    return User.model_validate(returned_only(ctx.auth.schema["user"], row))


async def _existing_pair(
    ctx: EndpointContext,
    provider: OAuthProvider,
    account: dict[str, Any],
    tokens: ProviderTokens,
) -> User:
    await ctx.adapter.update(
        "account",
        [Where("id", account["id"])],
        {"updated_at": ctx.clock.now(), **_token_fields(ctx, provider, tokens)},
    )
    return await _user(ctx, account["user_id"])


async def _resolve_user(
    ctx: EndpointContext,
    provider: OAuthProvider,
    profile: ProviderUser,
    tokens: ProviderTokens,
) -> User:
    """Apply the section 11 linking rules and return the user to sign in."""
    account = await _find_pair(ctx, provider, profile)
    if account is not None:
        return await _existing_pair(ctx, provider, account, tokens)
    if not profile.email:
        raise AuthError("PROVIDER_ERROR", 502, "The provider shared no email address")
    email = profile.email.strip().lower()
    existing = await ctx.adapter.find_one("user", [Where("email", email)])
    if existing is not None:
        linking = ctx.auth.config.account_linking
        trusted = provider.id in linking.trusted_providers
        if not (
            linking.enabled
            and profile.email_verified
            and (existing["email_verified"] or trusted)
        ):
            raise AuthError("ACCOUNT_NOT_LINKED", 409)
        if not existing["email_verified"]:
            await _claim_unverified(ctx, existing["id"])
        user_id = existing["id"]
    else:
        user = await ctx.auth.create_user_record(
            ctx,
            {
                "email": email,
                "email_verified": profile.email_verified,
                "name": profile.name,
                "image": profile.image,
            },
        )
        user_id = user.id
    try:
        await _add_account(ctx, provider, profile, tokens, user_id)
    except UniqueViolation:
        # A concurrent callback linked the same pair first: treat it as existing.
        account = await _find_pair(ctx, provider, profile)
        if account is None or account["user_id"] != user_id:
            raise AuthError("ACCOUNT_NOT_LINKED", 409) from None
    return await _user(ctx, user_id)


async def _claim_unverified(ctx: EndpointContext, user_id: str) -> None:
    """A trusted provider proved the email for a local account nobody verified.

    Whoever set that account's password never proved the address, so the password
    goes (pre-account hijacking) and so do its sessions. The owner can set a new
    password with a reset.
    """
    await ctx.adapter.delete(
        "account", [Where("user_id", user_id), Where("provider_id", _CREDENTIAL)]
    )
    await ctx.sessions.revoke_all(ctx, user_id)
    await ctx.adapter.update(
        "user",
        [Where("id", user_id)],
        {"email_verified": True, "updated_at": ctx.clock.now()},
    )
    await ctx.emit("user.email_verified", user_id=user_id)


async def _link(
    ctx: EndpointContext,
    provider: OAuthProvider,
    profile: ProviderUser,
    tokens: ProviderTokens,
    user_id: str,
) -> None:
    account = await _find_pair(ctx, provider, profile)
    if account is not None:
        if account["user_id"] != user_id:
            raise AuthError("ACCOUNT_NOT_LINKED", 409)
        await _existing_pair(ctx, provider, account, tokens)
        return
    user = await _user(ctx, user_id)
    same_email = (profile.email or "").strip().lower() == user.email
    if not same_email and not ctx.auth.config.account_linking.allow_different_emails:
        raise AuthError("ACCOUNT_NOT_LINKED", 409)
    try:
        await _add_account(ctx, provider, profile, tokens, user_id)
    except UniqueViolation:
        account = await _find_pair(ctx, provider, profile)
        if account is None or account["user_id"] != user_id:
            raise AuthError("ACCOUNT_NOT_LINKED", 409) from None


# ---------------------------------------------------------------- other endpoints


async def _social_callback_post(ctx: EndpointContext, form: CallbackIn) -> AuthResponse:
    provider = _provider(ctx, ctx.path_params["provider"])
    if provider.callback_method != "POST":
        raise AuthError("NOT_FOUND", 404)
    # A cross-site form POST does not carry the Lax state cookie: continue as a GET,
    # where the browser sends it and the normal checks run.
    params = {
        key: value
        for key, value in form.model_dump().items()
        if isinstance(value, str) and value
    }
    target = _redirect_uri(ctx, provider.id)
    return AuthResponse(redirect=f"{target}?{urlencode(params)}" if params else target)


async def _list_accounts(ctx: EndpointContext, _: None) -> AccountListOut:
    rows = await ctx.adapter.find_many(
        "account", [Where("user_id", _principal_user(ctx))]
    )
    rows.sort(key=lambda row: row["created_at"])
    return AccountListOut(
        accounts=[
            AccountOut(
                id=row["id"],
                provider_id=row["provider_id"],
                account_id=row["account_id"],
                scope=row.get("scope"),
                created_at=row["created_at"],
            )
            for row in rows
        ]
    )


async def _unlink_account(ctx: EndpointContext, body: UnlinkAccountIn) -> StatusOut:
    user_id = _principal_user(ctx)
    rows = await ctx.adapter.find_many("account", [Where("user_id", user_id)])
    matches = [
        row
        for row in rows
        if row["provider_id"] == body.provider_id
        and (body.account_id is None or row["account_id"] == body.account_id)
    ]
    if not matches:
        raise AuthError("NOT_FOUND", 404)
    if len(matches) > 1:
        raise AuthError("INVALID_REQUEST", 400, "Give account_id: several match")
    methods = sum(
        1
        for row in rows
        if row["provider_id"] != _CREDENTIAL or row.get("password_hash")
    )
    if "passkey" in ctx.auth.plugin_ids:
        methods += await ctx.adapter.count("passkey", [Where("user_id", user_id)])
    if methods <= 1:
        raise AuthError("LAST_SIGN_IN_METHOD", 409)
    await ctx.adapter.delete("account", [Where("id", matches[0]["id"])])
    await ctx.emit("account.unlinked", user_id=user_id, provider_id=body.provider_id)
    return StatusOut(status="ok")


def social_plugin() -> Plugin:
    """Return the ``social`` plugin (CONTRACTS 13.2); providers come from
    ``ctx.auth.providers``."""
    tags = ("social",)
    return Plugin(
        id="social",
        endpoints=(
            Endpoint(
                "sign_in_social",
                "POST",
                "/sign-in/social",
                _sign_in_social,
                input=SignInSocialIn,
                output=RedirectOut,
                summary="Start a social sign-in",
                tags=tags,
            ),
            Endpoint(
                "social_callback",
                "GET",
                "/callback/{provider}",
                _social_callback,
                input=CallbackIn,
                summary="Social sign-in callback",
                tags=tags,
            ),
            Endpoint(
                "social_callback_post",
                "POST",
                "/callback/{provider}",
                _social_callback_post,
                input=CallbackIn,
                input_format="form",
                summary="Social sign-in callback (form_post providers)",
                tags=tags,
            ),
            Endpoint(
                "link_social",
                "POST",
                "/link-social",
                _link_social,
                input=LinkSocialIn,
                output=RedirectOut,
                auth="session",
                summary="Link a social account",
                tags=tags,
            ),
            Endpoint(
                "list_accounts",
                "GET",
                "/accounts",
                _list_accounts,
                output=AccountListOut,
                auth="session",
                summary="List your linked accounts",
                tags=tags,
            ),
            Endpoint(
                "unlink_account",
                "POST",
                "/unlink-account",
                _unlink_account,
                input=UnlinkAccountIn,
                output=StatusOut,
                auth="session",
                fresh_session=True,
                summary="Unlink an account",
                tags=tags,
            ),
        ),
    )
