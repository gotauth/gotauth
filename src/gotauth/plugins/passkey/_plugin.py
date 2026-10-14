"""The ``passkey`` plugin (work package P3): add passkeys to an account and sign in
with them, usernameless. py_webauthn verifies the ceremonies; GotAuth owns the
challenges, the storage and the sessions."""

from __future__ import annotations

import importlib.util
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PydanticField

from gotauth.contracts.adapter import Where
from gotauth.contracts.config import GotAuthInstance
from gotauth.contracts.core_schema import User
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError, ConfigError, UniqueViolation
from gotauth.contracts.http import SetCookie
from gotauth.contracts.http_models import ChallengeOut, SignInOut, StatusOut
from gotauth.contracts.primitives import to_timedelta
from gotauth.contracts.protection import normalize_origin
from gotauth.contracts.schema import Field, ModelSchema, Reference, returned_only
from gotauth.contracts.sessions import cookie_name, secure_cookies

__all__ = ["PASSKEY_MODEL", "passkey"]

logger = logging.getLogger("gotauth.passkey")

PASSKEY_MODEL = ModelSchema(
    name="passkey",
    fields=MappingProxyType(
        {
            "user_id": Field(
                "string", index=True, references=Reference("user", on_delete="cascade")
            ),
            "credential_id": Field("string", unique=True),  # base64url
            "public_key": Field("text", returned=False),  # base64url COSE key
            "sign_count": Field("integer", default=0),
            "transports": Field("string_list", default=list),
            "device_type": Field("string"),  # "single_device" | "multi_device"
            "backed_up": Field("boolean", default=False),
            "name": Field("string", required=False),
            "created_at": Field("datetime"),
            "last_used_at": Field("datetime", required=False),
        }
    ),
)
"""The ``passkey`` model: one row per registered credential."""

ERROR_CODES: dict[str, tuple[int, str]] = {
    "PASSKEY_CHALLENGE_INVALID": (400, "The passkey challenge is invalid or expired"),
    "PASSKEY_VERIFICATION_FAILED": (401, "The passkey could not be verified"),
    "PASSKEY_ALREADY_REGISTERED": (409, "This passkey is already registered"),
}

CHALLENGE_TTL = to_timedelta("5m")
_SIGN_IN = "passkey:sign_in"


def _error(code: str) -> AuthError:
    status, message = ERROR_CODES[code]
    return AuthError(code, status, message)


# ---------------------------------------------------------------- models


class PasskeyOut(BaseModel):
    """A passkey without its public key."""

    id: str
    name: str | None
    credential_id: str
    transports: list[str]
    device_type: Literal["single_device", "multi_device"]
    backed_up: bool
    created_at: datetime
    last_used_at: datetime | None


class CreationOptionsOut(BaseModel):
    """``PublicKeyCredentialCreationOptions`` as WebAuthn JSON (base64url values),
    for ``navigator.credentials.create()``."""

    model_config = ConfigDict(extra="allow")

    challenge: str
    rp: dict[str, Any]  # Any: JSON
    user: dict[str, Any]  # Any: JSON
    pubKeyCredParams: list[dict[str, Any]]
    excludeCredentials: list[dict[str, Any]] = []


class RequestOptionsOut(BaseModel):
    """``PublicKeyCredentialRequestOptions`` as WebAuthn JSON, for
    ``navigator.credentials.get()``."""

    model_config = ConfigDict(extra="allow")

    challenge: str
    rpId: str
    allowCredentials: list[dict[str, Any]] = []


class PasskeyListOut(BaseModel):
    """``list_passkeys`` output."""

    passkeys: list[PasskeyOut]


class RegisterIn(BaseModel):
    """``verify_passkey_registration`` input: the credential from
    ``navigator.credentials.create()`` as JSON, and a name for it."""

    model_config = ConfigDict(extra="forbid")

    response: dict[str, Any]  # Any: the WebAuthn JSON credential
    name: str | None = PydanticField(default=None, max_length=100)


class SignInIn(BaseModel):
    """``sign_in_passkey`` input: the ``navigator.credentials.get()`` credential."""

    model_config = ConfigDict(extra="forbid")

    response: dict[str, Any]  # Any: the WebAuthn JSON credential
    remember_me: bool = True


class RenameIn(BaseModel):
    """``rename_passkey`` input."""

    model_config = ConfigDict(extra="forbid")

    name: str = PydanticField(min_length=1, max_length=100)


# ---------------------------------------------------------------- settings


@dataclass(frozen=True)
class _Settings:
    rp_id: str | None
    rp_name: str | None
    user_verification: Literal["required", "preferred", "discouraged"]
    reject_sign_count_regression: bool

    def rp(self, auth: GotAuthInstance) -> tuple[str, str, list[str]]:
        """``(rp_id, rp_name, origins)``: the origins are ``base_url``'s origin plus
        the exact (non-wildcard) trusted origins."""
        base = urlsplit(auth.config.base_url)
        rp_id = (self.rp_id or base.hostname or "").lower()
        origins: list[str] = []
        # As browsers report them in clientDataJSON: lower case, no default port.
        for origin in (auth.config.base_url, *auth.config.trusted_origins):
            normalized = None if "*" in origin else normalize_origin(origin)
            if normalized is not None and normalized not in origins:
                origins.append(normalized)
        return rp_id, self.rp_name or rp_id, origins


def _registrable(rp_id: str, origin: str) -> bool:
    host = urlsplit(origin).hostname or ""
    return host == rp_id or host.endswith("." + rp_id)


def _cookie(ctx: EndpointContext) -> str:
    config = ctx.auth.config
    return cookie_name(
        "passkey_challenge",
        base_url=config.base_url,
        prefix=config.advanced.cookie_prefix,
    )


def _session_user(ctx: EndpointContext) -> str:
    principal = ctx.principal
    if principal is None or principal.user_id is None:  # the pipeline checked
        raise AuthError("UNAUTHENTICATED", 401)
    return principal.user_id


def _out(ctx: EndpointContext, row: dict[str, Any]) -> PasskeyOut:  # Any: row
    return PasskeyOut.model_validate(returned_only(ctx.auth.schema["passkey"], row))


def passkey(
    *,
    rp_id: str | None = None,
    rp_name: str | None = None,
    user_verification: Literal["required", "preferred", "discouraged"] = "preferred",
    reject_sign_count_regression: bool = True,
) -> Plugin:
    """Return the ``passkey`` plugin. Needs ``pip install "gotauth[passkey]"``.

    Args:
        rp_id: The relying party id; default: the host of ``base_url``. Every origin
            must be this host or a subdomain of it. Changing it later orphans every
            registered passkey.
        rp_name: The name browsers show; default: ``rp_id``.
        user_verification: WebAuthn user verification (PIN, biometrics).
        reject_sign_count_regression: Refuse an assertion whose signature counter did
            not go up (a cloned authenticator). Synced passkeys that always report 0
            are accepted.

    Returns:
        The plugin.

    Raises:
        ConfigError: If the ``passkey`` extra is not installed.
    """
    if importlib.util.find_spec("webauthn") is None:
        msg = 'passkey() needs the passkey extra: pip install "gotauth[passkey]"'
        raise ConfigError(msg)
    from gotauth.plugins.passkey import _ceremony as ceremony

    settings = _Settings(
        rp_id=rp_id,
        rp_name=rp_name,
        user_verification=user_verification,
        reject_sign_count_regression=reject_sign_count_regression,
    )

    async def init(auth: GotAuthInstance) -> None:
        the_rp_id, _, origins = settings.rp(auth)
        bad = [origin for origin in origins if not _registrable(the_rp_id, origin)]
        if not the_rp_id or bad:
            msg = f"passkey(): rp_id {the_rp_id!r} does not cover the origins {bad}"
            raise ConfigError(msg)

    # -------------------------------------------------------- challenges

    def slots(ctx: EndpointContext) -> dict[str, str]:
        """The browser's pending challenge ids, by ceremony (``register``,
        ``sign_in``): one cookie, so starting one ceremony keeps the other."""
        signed = ctx.request.cookies.get(_cookie(ctx))
        value = (
            ctx.crypto.unsign(signed, purpose="passkey_challenge") if signed else None
        )
        found: dict[str, str] = {}
        for part in (value or "").split("|"):
            kind, _, row_id = part.partition(":")
            if kind in ("register", "sign_in") and row_id:
                found[kind] = row_id
        return found

    def write_slots(ctx: EndpointContext, found: dict[str, str]) -> None:
        value = "|".join(f"{kind}:{row_id}" for kind, row_id in sorted(found.items()))
        ctx.set_cookie(
            SetCookie(
                name=_cookie(ctx),
                value=ctx.crypto.sign(value, purpose="passkey_challenge")
                if value
                else "",
                max_age=int(CHALLENGE_TTL.total_seconds()) if value else 0,
                secure=secure_cookies(ctx.auth.config.base_url),
            )
        )

    async def new_challenge(ctx: EndpointContext, kind: str, identifier: str) -> bytes:
        """A random challenge, stored hashed and bound to this browser by a cookie."""
        challenge = ctx.crypto.random_token(nbytes=32).encode()
        row_id = ctx.ids.new("ver")
        now = ctx.clock.now()
        # 5. No piling up: the user's earlier registration challenge, and every
        # expired sign-in challenge, go.
        if kind == "register":
            await ctx.adapter.delete("verification", [Where("identifier", identifier)])
        else:
            await ctx.adapter.delete(
                "verification",
                [Where("identifier", identifier), Where("expires_at", now, "lte")],
            )
        await ctx.adapter.create(
            "verification",
            {
                "id": row_id,
                "identifier": identifier,
                "value_hash": ctx.crypto.hash_token(ceremony.b64(challenge)),
                "expires_at": now + CHALLENGE_TTL,
                "created_at": now,
            },
        )
        found = slots(ctx)
        found[kind] = row_id
        write_slots(ctx, found)
        return challenge

    async def consume_challenge(
        ctx: EndpointContext, kind: str, identifier: str, response: dict[str, Any]
    ) -> bytes:
        """Consume the challenge the response signed: it must be this browser's, for
        this ceremony, unexpired and unused. Returns the challenge bytes."""
        found = slots(ctx)
        row_id = found.get(kind)
        challenge = ceremony.client_challenge(response)
        if row_id is None or challenge is None:
            raise _error("PASSKEY_CHALLENGE_INVALID")
        consumed = await ctx.adapter.delete(
            "verification",
            [
                Where("id", row_id),
                Where("identifier", identifier),
                Where("value_hash", ctx.crypto.hash_token(ceremony.b64(challenge))),
                Where("expires_at", ctx.clock.now(), "gt"),
            ],
        )
        if consumed != 1:
            raise _error("PASSKEY_CHALLENGE_INVALID")
        del found[kind]
        write_slots(ctx, found)
        return challenge

    # -------------------------------------------------------- registration

    async def registration_options(ctx: EndpointContext, _: None) -> CreationOptionsOut:
        user_id = _session_user(ctx)
        user = await ctx.adapter.find_one("user", [Where("id", user_id)])
        if user is None:
            raise AuthError("UNAUTHENTICATED", 401)
        existing = await ctx.adapter.find_many("passkey", [Where("user_id", user_id)])
        rp_id_value, rp_name_value, _origins = settings.rp(ctx.auth)
        challenge = await new_challenge(ctx, "register", f"passkey:register:{user_id}")
        return CreationOptionsOut.model_validate(
            ceremony.registration_options(
                rp_id=rp_id_value,
                rp_name=rp_name_value,
                user_id=user_id,
                user_name=str(user["email"]),
                display_name=str(user.get("name") or user["email"]),
                challenge=challenge,
                exclude=[
                    (row["credential_id"], row.get("transports") or [])
                    for row in existing
                ],
                user_verification=settings.user_verification,
            )
        )

    async def verify_registration(ctx: EndpointContext, body: RegisterIn) -> PasskeyOut:
        user_id = _session_user(ctx)
        challenge = await consume_challenge(
            ctx, "register", f"passkey:register:{user_id}", body.response
        )
        rp_id_value, _name, origins = settings.rp(ctx.auth)
        try:
            verified = ceremony.verify_registration(
                body.response,
                challenge=challenge,
                rp_id=rp_id_value,
                origins=origins,
                require_user_verification=settings.user_verification == "required",
            )
        except ceremony.Rejected as exc:
            raise _error("PASSKEY_VERIFICATION_FAILED") from exc
        taken = await ctx.adapter.find_one(
            "passkey", [Where("credential_id", verified.credential_id)]
        )
        if taken is not None:
            raise _error("PASSKEY_ALREADY_REGISTERED")
        try:
            row = await ctx.adapter.create(
                "passkey",
                {
                    "id": ctx.ids.new("pky"),
                    "user_id": user_id,
                    "credential_id": verified.credential_id,
                    "public_key": verified.public_key,
                    "sign_count": verified.sign_count,
                    "transports": verified.transports,
                    "device_type": verified.device_type,
                    "backed_up": verified.backed_up,
                    "name": body.name,
                    "created_at": ctx.clock.now(),
                    "last_used_at": None,
                },
            )
        except UniqueViolation as exc:  # registered concurrently
            raise _error("PASSKEY_ALREADY_REGISTERED") from exc
        await ctx.emit("passkey.added", user_id=user_id, passkey_id=row["id"])
        return _out(ctx, row)

    # -------------------------------------------------------- sign-in

    async def sign_in_options(ctx: EndpointContext, _: None) -> RequestOptionsOut:
        rp_id_value, _name, _origins = settings.rp(ctx.auth)
        challenge = await new_challenge(ctx, "sign_in", _SIGN_IN)
        return RequestOptionsOut.model_validate(
            ceremony.authentication_options(
                rp_id=rp_id_value,
                challenge=challenge,
                user_verification=settings.user_verification,
            )
        )

    async def sign_in(ctx: EndpointContext, body: SignInIn) -> SignInOut | ChallengeOut:
        challenge = await consume_challenge(ctx, "sign_in", _SIGN_IN, body.response)
        presented = ceremony.assertion_ids(body.response)
        # Unknown credentials and wrong owners answer like a bad signature, so
        # credential ids cannot be probed.
        if presented is None:
            raise _error("PASSKEY_VERIFICATION_FAILED")
        credential_id, user_handle = presented
        row = await ctx.adapter.find_one(
            "passkey", [Where("credential_id", credential_id)]
        )
        if row is None or user_handle != row["user_id"]:
            raise _error("PASSKEY_VERIFICATION_FAILED")
        rp_id_value, _name, origins = settings.rp(ctx.auth)
        stored = int(row.get("sign_count") or 0)
        try:
            new_count, user_verified = ceremony.verify_assertion(
                body.response,
                challenge=challenge,
                rp_id=rp_id_value,
                origins=origins,
                public_key=row["public_key"],
                current_sign_count=stored
                if settings.reject_sign_count_regression
                else 0,
                require_user_verification=settings.user_verification == "required",
            )
        except ceremony.Rejected as exc:
            if "sign count" in str(exc).lower():
                logger.warning(
                    "gotauth: passkey %s: the sign count did not go up (cloned?)",
                    row["id"],
                )
            raise _error("PASSKEY_VERIFICATION_FAILED") from exc
        if not user_verified and settings.user_verification != "discouraged":
            # Possession alone (no PIN or biometrics) is one factor: it must not
            # count as a passkey sign-in, which two-factor lets through.
            raise _error("PASSKEY_VERIFICATION_FAILED")
        # The consumed challenge already makes each assertion single-use.
        await ctx.adapter.update(
            "passkey",
            [Where("id", row["id"])],
            {"sign_count": new_count, "last_used_at": ctx.clock.now()},
        )
        user_row = await ctx.adapter.find_one("user", [Where("id", row["user_id"])])
        if user_row is None:
            raise _error("PASSKEY_VERIFICATION_FAILED")
        user = User.model_validate(returned_only(ctx.auth.schema["user"], user_row))
        return await ctx.auth.complete_sign_in(
            ctx, user, method="passkey", remember_me=body.remember_me
        )

    # -------------------------------------------------------- management

    async def owned(ctx: EndpointContext) -> dict[str, Any]:  # Any: row
        user_id = _session_user(ctx)
        row = await ctx.adapter.find_one(
            "passkey", [Where("id", ctx.path_params["id"])]
        )
        if row is None or row["user_id"] != user_id:
            raise AuthError("NOT_FOUND", 404)
        return row

    async def list_passkeys(ctx: EndpointContext, _: None) -> PasskeyListOut:
        rows = await ctx.adapter.find_many(
            "passkey", [Where("user_id", _session_user(ctx))]
        )
        rows.sort(key=lambda row: (row["created_at"], row["id"]))
        return PasskeyListOut(passkeys=[_out(ctx, row) for row in rows])

    async def rename(ctx: EndpointContext, body: RenameIn) -> PasskeyOut:
        row = await owned(ctx)
        updated = await ctx.adapter.update(
            "passkey", [Where("id", row["id"])], {"name": body.name}
        )
        return _out(ctx, updated or row)

    async def delete(ctx: EndpointContext, _: None) -> StatusOut:
        row = await owned(ctx)
        user_id = row["user_id"]
        # Writing the user row first takes its lock, so two deletes for one user
        # run one after the other and cannot both pass the check below.
        await ctx.adapter.update(
            "user", [Where("id", user_id)], {"updated_at": ctx.clock.now()}
        )
        others = await ctx.adapter.count(
            "passkey", [Where("user_id", user_id), Where("id", row["id"], "ne")]
        )
        accounts = await ctx.adapter.find_many("account", [Where("user_id", user_id)])
        # As social's unlink counts them: a password only once it is set.
        methods = others + sum(
            1
            for account in accounts
            if account["provider_id"] != "credential" or account.get("password_hash")
        )
        if methods == 0:
            raise AuthError("LAST_SIGN_IN_METHOD", 409)
        await ctx.adapter.delete("passkey", [Where("id", row["id"])])
        await ctx.emit("passkey.removed", user_id=row["user_id"], passkey_id=row["id"])
        return StatusOut(status="ok")

    tags = ("passkeys",)
    endpoints: Sequence[Endpoint[Any, Any]] = (
        Endpoint(
            "get_passkey_registration_options",
            "POST",
            "/passkey/register/options",
            registration_options,
            output=CreationOptionsOut,
            auth="session",
            summary="Options for navigator.credentials.create()",
            tags=tags,
        ),
        Endpoint(
            "verify_passkey_registration",
            "POST",
            "/passkey/register/verify",
            verify_registration,
            input=RegisterIn,
            output=PasskeyOut,
            auth="session",
            summary="Add a passkey to your account",
            tags=tags,
        ),
        Endpoint(
            "get_passkey_sign_in_options",
            "POST",
            "/passkey/sign-in/options",
            sign_in_options,
            output=RequestOptionsOut,
            summary="Options for navigator.credentials.get() (usernameless)",
            tags=tags,
        ),
        Endpoint(
            "sign_in_passkey",
            "POST",
            "/passkey/sign-in/verify",
            sign_in,
            input=SignInIn,
            summary="Sign in with a passkey",
            tags=tags,
        ),
        Endpoint(
            "list_passkeys",
            "GET",
            "/passkeys",
            list_passkeys,
            output=PasskeyListOut,
            auth="session",
            summary="List your passkeys",
            tags=tags,
        ),
        Endpoint(
            "rename_passkey",
            "PATCH",
            "/passkeys/{id}",
            rename,
            input=RenameIn,
            output=PasskeyOut,
            auth="session",
            summary="Rename a passkey",
            tags=tags,
        ),
        Endpoint(
            "delete_passkey",
            "DELETE",
            "/passkeys/{id}",
            delete,
            output=StatusOut,
            auth="session",
            fresh_session=True,
            summary="Remove a passkey",
            tags=tags,
        ),
    )
    return Plugin(
        id="passkey",
        schema={"passkey": PASSKEY_MODEL},
        endpoints=tuple(endpoints),
        error_codes=ERROR_CODES,
        init=init,
    )
