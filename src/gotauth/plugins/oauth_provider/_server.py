"""The OAuth 2.1 authorization server and OIDC provider: flows, tokens and checks."""

from __future__ import annotations

import base64
import html
import json
from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict

from gotauth.contracts.adapter import Where
from gotauth.contracts.core_schema import User
from gotauth.contracts.endpoints import EndpointContext
from gotauth.contracts.errors import AuthError
from gotauth.contracts.http import AuthResponse
from gotauth.contracts.primitives import to_timedelta
from gotauth.contracts.principal import Principal
from gotauth.contracts.schema import returned_only
from gotauth.contracts.sessions import TOKEN_PREFIXES

from ._clients import ClientStore, authenticate_client, is_cimd_url, oauth_error
from ._keys import KeyStore, TokenRejected
from ._rules import (
    Settings,
    is_loopback_redirect,
    normalize_resource,
    redirect_matches,
)

__all__ = ["AuthorizeIn", "ConsentIn", "OAuthServer", "TokenIn", "TokenRequestIn"]

CODE_PREFIX = TOKEN_PREFIXES["oauth_authorization_code"]
REFRESH_PREFIX = TOKEN_PREFIXES["oauth_refresh_token"]
_CODE_TTL = timedelta(seconds=60)
_CONSENT_TTL = 600  # seconds
_ACCEPT = {"true", "yes", "1", "on", "allow", "accept"}


class AuthorizeIn(BaseModel):
    """``oauth_authorize`` query; checked by hand so errors follow RFC 6749."""

    model_config = ConfigDict(extra="ignore")

    response_type: str | None = None
    client_id: str | None = None
    redirect_uri: str | None = None
    scope: str | None = None
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    nonce: str | None = None
    prompt: str | None = None
    resource: str | None = None


class ConsentIn(BaseModel):
    """``oauth_consent`` form."""

    model_config = ConfigDict(extra="ignore")

    consent_id: str
    accept: str = "false"
    scopes: str | None = None


class TokenIn(BaseModel):
    """``oauth_token`` form."""

    model_config = ConfigDict(extra="ignore")

    grant_type: str | None = None
    code: str | None = None
    redirect_uri: str | None = None
    code_verifier: str | None = None
    refresh_token: str | None = None
    scope: str | None = None
    resource: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class TokenRequestIn(BaseModel):
    """``oauth_introspect`` and ``oauth_revoke`` form."""

    model_config = ConfigDict(extra="ignore")

    token: str | None = None
    token_type_hint: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _with_query(url: str, params: Mapping[str, str | None]) -> str:
    parts = urlsplit(url)
    extra = urlencode({k: v for k, v in params.items() if v is not None})
    query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit(parts._replace(query=query))


def _grant_error(error: str) -> AuthResponse:
    """An RFC 6749 error as a response, so writes made before it (revocations of a
    replayed code's or reused refresh token's family) are committed."""
    return AuthResponse(status=400, body={"error": error})


def _scopes(text: str | None) -> list[str]:
    return sorted({scope for scope in (text or "").split() if scope})


_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;
padding:0 1rem;color:#1f2328;line-height:1.5}}
.warn{{border:1px solid #9a6700;background:#fff8c5;padding:.75rem;border-radius:6px}}
button{{font:inherit;padding:.5rem 1rem;margin-right:.5rem;border-radius:6px;
border:1px solid #1f2328;cursor:pointer}}
button.primary{{background:#1f2328;color:#fff}}
</style></head>
<body><main>{body}</main></body></html>"""


def _page(title: str, body: str, status: int = 200) -> AuthResponse:
    return AuthResponse(
        status=status,
        html=_PAGE.format(title=html.escape(title), body=body),
        headers={
            "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; "
            "form-action 'self' https: http:; frame-ancestors 'none'",
            "x-frame-options": "DENY",
            "cache-control": "no-store",
        },
    )


def _error_page(message: str) -> AuthResponse:
    """Errors that must not redirect: unknown client or redirect URI."""
    return _page(
        "Authorization error",
        f"<h1>Authorization error</h1><p>{html.escape(message)}</p>",
        status=400,
    )


class OAuthServer:
    """Holds the settings, keys and clients; the endpoint handlers are its methods."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.keys = KeyStore(settings)
        self.clients = ClientStore(settings)

    # ------------------------------------------------------------ basics

    @staticmethod
    def issuer(ctx: EndpointContext) -> str:
        config = ctx.auth.config
        return config.base_url.rstrip("/") + config.base_path.rstrip("/")

    def metadata(self, ctx: EndpointContext) -> dict[str, Any]:  # Any: JSON
        issuer = self.issuer(ctx)
        document: dict[str, Any] = {  # Any: JSON
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth2/authorize",
            "token_endpoint": f"{issuer}/oauth2/token",
            "jwks_uri": f"{issuer}/oauth2/jwks",
            "userinfo_endpoint": f"{issuer}/oauth2/userinfo",
            "introspection_endpoint": f"{issuer}/oauth2/introspect",
            "revocation_endpoint": f"{issuer}/oauth2/revoke",
            "scopes_supported": list(self.settings.scopes),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "introspection_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [self.settings.signing_alg],
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "nonce",
                "name",
                "picture",
                "email",
                "email_verified",
            ],
        }
        if self.settings.allow_cimd:
            document["client_id_metadata_document_supported"] = True
        if self.settings.allow_dynamic_registration:
            document["registration_endpoint"] = f"{issuer}/oauth2/register"
        return document

    async def _signer(self, ctx: EndpointContext) -> tuple[str, str, Any]:  # Any: key
        await self.keys.ensure(ctx.adapter, ctx.crypto, ctx.clock, ctx.ids)
        return await self.keys.signer(ctx.adapter, ctx.crypto)

    # ------------------------------------------------------------ authorize

    async def authorize(self, ctx: EndpointContext, query: AuthorizeIn) -> AuthResponse:
        raw = parse_qsl(urlsplit(ctx.request.url).query, keep_blank_values=True)
        if not query.client_id:
            return _error_page("The request has no client_id.")
        try:
            client = await self.clients.get(ctx, query.client_id)
        except AuthError:
            return _error_page("The client's metadata document could not be used.")
        if client is None or client.get("disabled_at") is not None:
            return _error_page("Unknown client.")
        registered: list[str] = list(client["redirect_uris"])
        redirect_uri = query.redirect_uri
        if (
            redirect_uri is None
            and len(registered) == 1
            and not is_loopback_redirect(registered[0])
        ):
            redirect_uri = registered[0]
        if redirect_uri is None or not any(
            redirect_matches(r, redirect_uri) for r in registered
        ):
            return _error_page("The redirect URI is not registered for this client.")
        issuer = self.issuer(ctx)

        def fail(error: str, description: str | None = None) -> AuthResponse:
            # RFC 9207: iss on every redirect back to the client, errors included.
            return AuthResponse(
                redirect=_with_query(
                    redirect_uri,
                    {
                        "error": error,
                        "error_description": description,
                        "state": query.state,
                        "iss": issuer,
                    },
                )
            )

        if query.response_type != "code":
            return fail("unsupported_response_type")
        if query.code_challenge_method != "S256" or not query.code_challenge:
            return fail("invalid_request", "PKCE with S256 is required")
        if len(query.code_challenge) < 43 or len(query.code_challenge) > 128:
            return fail("invalid_request", "code_challenge has the wrong length")
        requested = _scopes(query.scope)
        allowed = set(client["scopes"]) & set(self.settings.scopes)
        if not set(requested) <= allowed:
            return fail("invalid_scope")
        resources = [value for key, value in raw if key == "resource"]
        resource = self.settings.resource(resources)
        if resource is False or (self.settings.mcp and resource is None):
            return fail("invalid_target")
        principal = ctx.principal
        prompt = set((query.prompt or "").split())
        if principal is None or principal.via != "session" or principal.user_id is None:
            if "none" in prompt:
                return fail("login_required")
            login = _with_query(
                self.settings.login_page, {"callback_url": ctx.request.url}
            )
            if ctx.request.headers.get("accept", "").startswith("application/json"):
                return AuthResponse(body={"url": login})
            return AuthResponse(redirect=login)
        user_id = principal.user_id
        resource_value = cast(str | None, resource)
        cimd_loopback = client["registration"] == "cimd" and is_loopback_redirect(
            redirect_uri
        )
        if (
            "consent" not in prompt
            and not cimd_loopback
            and await self._has_consent(
                ctx, user_id, client["client_id"], requested, resource_value
            )
        ):
            code = await self._issue_code(
                ctx,
                client,
                user_id,
                redirect_uri,
                requested,
                resource_value,
                query.code_challenge,
                query.nonce,
            )
            return AuthResponse(
                redirect=_with_query(
                    redirect_uri, {"code": code, "state": query.state, "iss": issuer}
                )
            )
        if "none" in prompt:
            return fail("consent_required")
        consent_id = self._consent_id(
            ctx,
            {
                "c": client["client_id"],
                "r": redirect_uri,
                "s": requested,
                "res": resource_value,
                "st": query.state,
                "cc": query.code_challenge,
                "n": query.nonce,
                "u": user_id,
                "e": int(ctx.clock.now().timestamp()) + _CONSENT_TTL,
            },
        )
        return self._consent_screen(
            ctx, client, consent_id, requested, resource_value, redirect_uri
        )

    async def _has_consent(
        self,
        ctx: EndpointContext,
        user_id: str,
        client_id: str,
        scopes: Sequence[str],
        resource: str | None,
    ) -> bool:
        rows = await ctx.adapter.find_many(
            "oauth_consent", [Where("user_id", user_id), Where("client_id", client_id)]
        )
        return any(
            set(scopes) <= set(row["scopes"]) and row.get("resource") == resource
            for row in rows
        )

    @staticmethod
    def _consent_id(
        ctx: EndpointContext, payload: Mapping[str, Any]
    ) -> str:  # Any: JSON
        return ctx.crypto.sign(
            _b64(json.dumps(payload).encode()), purpose="oauth_consent"
        )

    def _consent_screen(
        self,
        ctx: EndpointContext,
        client: Mapping[str, Any],  # Any: row
        consent_id: str,
        scopes: Sequence[str],
        resource: str | None,
        redirect_uri: str,
    ) -> AuthResponse:
        redirect_host = urlsplit(redirect_uri).netloc
        loopback_only = all(
            is_loopback_redirect(uri) for uri in client["redirect_uris"]
        )
        client_id = str(client["client_id"])
        cimd_host = urlsplit(client_id).netloc if is_cimd_url(client_id) else None
        if ctx.request.headers.get("accept", "").startswith("application/json"):
            if self.settings.consent_page:
                return AuthResponse(
                    body={
                        "url": _with_query(
                            self.settings.consent_page, {"consent_id": consent_id}
                        )
                    }
                )
            return AuthResponse(
                body={
                    "consent_id": consent_id,
                    "client": {
                        "client_id": client["client_id"],
                        "name": client["name"],
                        "host": cimd_host,
                    },
                    "scopes": list(scopes),
                    "resource": resource,
                    "redirect_host": redirect_host,
                    "loopback_only": loopback_only,
                }
            )
        if self.settings.consent_page:
            return AuthResponse(
                redirect=_with_query(
                    self.settings.consent_page, {"consent_id": consent_id}
                )
            )
        name = html.escape(str(client["name"]))
        items = (
            "".join(f"<li><code>{html.escape(scope)}</code></li>" for scope in scopes)
            or "<li>Basic access</li>"
        )
        source = (
            f"<p>Client metadata from <strong>{html.escape(cimd_host)}</strong>.</p>"
            if cimd_host
            else ""
        )
        warning = (
            '<p class="warn">This app only uses local addresses. Any program on your '
            "computer could be asking. Continue only if you just started this sign-in "
            "yourself.</p>"
            if loopback_only
            else ""
        )
        target = (
            "<p>You will be sent back to "
            f"<strong>{html.escape(redirect_host)}</strong>.</p>"
        )
        audience = (
            f"<p>Access is for <code>{html.escape(resource)}</code>.</p>"
            if resource
            else ""
        )
        action = html.escape(self.issuer(ctx) + "/oauth2/consent")
        body = (
            f"<h1>Allow {name} to access your account?</h1>{source}{target}{warning}"
            f"<p>It will be able to:</p><ul>{items}</ul>{audience}"
            f'<form method="post" action="{action}">'
            '<input type="hidden" name="consent_id" '
            f'value="{html.escape(consent_id)}">'
            '<button class="primary" type="submit" name="accept" value="true">'
            "Allow</button>"
            '<button type="submit" name="accept" value="false">Deny</button>'
            "</form>"
        )
        return _page(f"Allow {client['name']}?", body)

    async def consent(self, ctx: EndpointContext, form: ConsentIn) -> AuthResponse:
        principal = ctx.principal
        if principal is None or principal.user_id is None:
            raise AuthError("UNAUTHENTICATED", 401)
        payload = self._read_consent(ctx, form.consent_id, principal.user_id)
        issuer = self.issuer(ctx)
        redirect_uri = str(payload["r"])
        if form.accept.lower() not in _ACCEPT:
            return AuthResponse(
                redirect=_with_query(
                    redirect_uri,
                    {
                        "error": "access_denied",
                        "state": payload.get("st"),
                        "iss": issuer,
                    },
                )
            )
        client = await ctx.adapter.find_one(
            "oauth_client", [Where("client_id", payload["c"])]
        )
        if client is None or client.get("disabled_at") is not None:
            raise AuthError("TOKEN_INVALID", 400, "Unknown client")
        requested = list(payload["s"])
        granted = (
            requested
            if form.scopes is None
            else sorted(set(_scopes(form.scopes)) & set(requested))
        )
        resource = cast(str | None, payload.get("res"))
        await self._store_consent(
            ctx, principal.user_id, client["client_id"], granted, resource
        )
        code = await self._issue_code(
            ctx,
            client,
            principal.user_id,
            redirect_uri,
            granted,
            resource,
            str(payload["cc"]),
            cast(str | None, payload.get("n")),
        )
        await ctx.emit(
            "oauth.consent_granted",
            user_id=principal.user_id,
            client_id=client["client_id"],
            scopes=granted,
        )
        return AuthResponse(
            redirect=_with_query(
                redirect_uri, {"code": code, "state": payload.get("st"), "iss": issuer}
            )
        )

    @staticmethod
    def _read_consent(
        ctx: EndpointContext, consent_id: str, user_id: str
    ) -> dict[str, Any]:  # Any: JSON
        encoded = ctx.crypto.unsign(consent_id, purpose="oauth_consent")
        try:
            payload = (
                cast(dict[str, Any], json.loads(_unb64(encoded))) if encoded else None
            )
        except ValueError:
            payload = None
        if (
            payload is None
            or payload.get("u") != user_id
            or int(payload.get("e", 0)) <= int(ctx.clock.now().timestamp())
        ):
            raise AuthError(
                "TOKEN_INVALID", 400, "The consent request is invalid or expired"
            )
        return payload

    @staticmethod
    async def _store_consent(
        ctx: EndpointContext,
        user_id: str,
        client_id: str,
        scopes: Sequence[str],
        resource: str | None,
    ) -> None:
        rows = await ctx.adapter.find_many(
            "oauth_consent", [Where("user_id", user_id), Where("client_id", client_id)]
        )
        for row in rows:
            if row.get("resource") == resource:
                merged = sorted(set(row["scopes"]) | set(scopes))
                await ctx.adapter.update(
                    "oauth_consent", [Where("id", row["id"])], {"scopes": merged}
                )
                return
        await ctx.adapter.create(
            "oauth_consent",
            {
                "id": ctx.ids.new("ocn"),
                "user_id": user_id,
                "client_id": client_id,
                "scopes": list(scopes),
                "resource": resource,
                "created_at": ctx.clock.now(),
            },
        )

    @staticmethod
    async def _issue_code(
        ctx: EndpointContext,
        client: Mapping[str, Any],  # Any: row
        user_id: str,
        redirect_uri: str,
        scopes: Sequence[str],
        resource: str | None,
        code_challenge: str,
        nonce: str | None,
    ) -> str:
        code = ctx.crypto.random_token(CODE_PREFIX)
        await ctx.adapter.create(
            "oauth_code",
            {
                "id": ctx.ids.new("cod"),
                "code_hash": ctx.crypto.hash_token(code),
                "client_id": client["client_id"],
                "user_id": user_id,
                "redirect_uri": redirect_uri,
                "scopes": list(scopes),
                "resource": resource,
                "code_challenge": code_challenge,
                "nonce": nonce,
                "expires_at": ctx.clock.now() + _CODE_TTL,
            },
        )
        return code

    # ------------------------------------------------------------ token endpoint

    async def token(
        self, ctx: EndpointContext, form: TokenIn
    ) -> dict[str, Any] | AuthResponse:  # Any: JSON
        grants = {
            "authorization_code": self._grant_code,
            "refresh_token": self._grant_refresh,
            "client_credentials": self._grant_client_credentials,
        }
        handler = grants.get(form.grant_type or "")
        if handler is None:
            raise oauth_error("unsupported_grant_type")
        client = await authenticate_client(
            ctx, self.clients, form.model_dump(exclude_none=True)
        )
        if form.grant_type not in client["grant_types"]:
            raise oauth_error("unauthorized_client")
        return await handler(ctx, client, form)

    def _requested_resource(self, form: TokenIn) -> str | bool | None:
        if form.resource is None:
            return None
        return normalize_resource(form.resource) or False

    async def _grant_code(
        self,
        ctx: EndpointContext,
        client: dict[str, Any],
        form: TokenIn,  # Any: row
    ) -> dict[str, Any] | AuthResponse:  # Any: JSON
        if not form.code or not form.code_verifier or not form.redirect_uri:
            raise oauth_error(
                "invalid_request",
                400,
                "code, code_verifier and redirect_uri are required",
            )
        code_hash = ctx.crypto.hash_token(form.code)
        row = await ctx.adapter.find_one("oauth_code", [Where("code_hash", code_hash)])
        now = ctx.clock.now()
        consumed = 0
        if row is not None:
            consumed = await ctx.adapter.delete(
                "oauth_code",
                [
                    Where("id", row["id"]),
                    Where("code_hash", code_hash),
                    Where("expires_at", now, "gt"),
                ],
            )
        if row is None or consumed != 1:
            # A replayed code: revoke whatever it already produced (RFC 6749 4.1.2).
            # Returned, not raised: raising would roll the revocation back.
            await self._revoke_family(ctx, code_hash)
            return _grant_error("invalid_grant")
        if (
            row["client_id"] != client["client_id"]
            or row["redirect_uri"] != form.redirect_uri
        ):
            raise oauth_error("invalid_grant")
        if not ctx.crypto.equal(
            ctx.crypto.pkce_s256(form.code_verifier), row["code_challenge"]
        ):
            raise oauth_error("invalid_grant", 400, "PKCE verification failed")
        requested = self._requested_resource(form)
        if requested is False or (
            requested is not None and requested != row.get("resource")
        ):
            raise oauth_error("invalid_target")
        return await self._mint(
            ctx,
            client,
            user_id=row["user_id"],
            scopes=list(row["scopes"]),
            resource=row.get("resource"),
            family_id=code_hash,
            nonce=row.get("nonce"),
            refresh="refresh_token" in client["grant_types"],
        )

    async def _grant_refresh(
        self,
        ctx: EndpointContext,
        client: dict[str, Any],
        form: TokenIn,  # Any: row
    ) -> dict[str, Any] | AuthResponse:  # Any: JSON
        if not form.refresh_token:
            raise oauth_error("invalid_request", 400, "refresh_token is required")
        token_hash = ctx.crypto.hash_token(form.refresh_token)
        row = await ctx.adapter.find_one(
            "oauth_token", [Where("refresh_token_hash", token_hash)]
        )
        if row is None or row["client_id"] != client["client_id"]:
            raise oauth_error("invalid_grant")
        now = ctx.clock.now()
        if row.get("revoked_at") is not None:
            # Reuse of a rotated or revoked token: the family is compromised.
            await self._revoke_family(ctx, row["family_id"])
            return _grant_error("invalid_grant")
        if row["expires_at"] <= now:
            raise oauth_error("invalid_grant")
        scopes = list(row["scopes"])
        if form.scope is not None:
            narrowed = _scopes(form.scope)
            if not set(narrowed) <= set(scopes):
                raise oauth_error("invalid_scope")
            scopes = narrowed
        requested = self._requested_resource(form)
        if requested is False or (
            requested is not None and requested != row.get("resource")
        ):
            raise oauth_error("invalid_target")
        rotated = await ctx.adapter.update(
            "oauth_token",
            [Where("id", row["id"]), Where("revoked_at", True, "is_null")],
            {"revoked_at": now},
        )
        if rotated is None:  # a concurrent refresh with the same token
            await self._revoke_family(ctx, row["family_id"])
            return _grant_error("invalid_grant")
        return await self._mint(
            ctx,
            client,
            user_id=row.get("user_id"),
            scopes=scopes,
            resource=row.get("resource"),
            family_id=row["family_id"],
            nonce=None,
            refresh=True,
            parent_expires=row["expires_at"],
        )

    async def _grant_client_credentials(
        self,
        ctx: EndpointContext,
        client: dict[str, Any],
        form: TokenIn,  # Any: row
    ) -> dict[str, Any] | AuthResponse:  # Any: JSON
        if client["type"] != "confidential":
            raise oauth_error("unauthorized_client")
        scopes = (
            _scopes(form.scope) if form.scope is not None else sorted(client["scopes"])
        )
        if not set(scopes) <= set(client["scopes"]) or "openid" in scopes:
            raise oauth_error("invalid_scope")
        resource: str | None = None
        if form.resource is not None:
            value = self.settings.resource([form.resource])
            if value is False:
                raise oauth_error("invalid_target")
            resource = cast(str | None, value)
        user_id: str | None = None
        agent_id = client.get("agent_id")
        if agent_id and "agent" in ctx.auth.schema:
            agent = await ctx.adapter.find_one("agent", [Where("id", agent_id)])
            if agent is None or agent.get("disabled_at") is not None:
                raise oauth_error("invalid_client", 401)
            if agent["owner_type"] == "user":
                user_id = agent["owner_id"]
        return await self._mint(
            ctx,
            client,
            user_id=user_id,
            scopes=scopes,
            resource=resource,
            family_id="fam_" + ctx.crypto.random_token(nbytes=16),
            nonce=None,
            refresh=False,
            subject=agent_id or client["client_id"],
        )

    async def _mint(
        self,
        ctx: EndpointContext,
        client: Mapping[str, Any],  # Any: row
        *,
        user_id: str | None,
        scopes: Sequence[str],
        resource: str | None,
        family_id: str,
        nonce: str | None,
        refresh: bool,
        subject: str | None = None,
        parent_expires: Any = None,  # Any: datetime of the rotated grant
    ) -> dict[str, Any]:  # Any: JSON
        now = ctx.clock.now()
        access_ttl = to_timedelta(self.settings.access_token_ttl)
        refresh_token = ctx.crypto.random_token(REFRESH_PREFIX) if refresh else None
        grant_expires = (
            parent_expires
            if parent_expires is not None
            else now
            + (to_timedelta(self.settings.refresh_token_ttl) if refresh else access_ttl)
        )
        row = await ctx.adapter.create(
            "oauth_token",
            {
                "id": ctx.ids.new("tok"),
                "refresh_token_hash": ctx.crypto.hash_token(refresh_token)
                if refresh_token
                else None,
                "family_id": family_id,
                "client_id": client["client_id"],
                "user_id": user_id,
                "agent_id": client.get("agent_id"),
                "scopes": list(scopes),
                "resource": resource,
                "expires_at": grant_expires,
                "created_at": now,
            },
        )
        issuer = self.issuer(ctx)
        kid, alg, key = await self._signer(ctx)
        claims: dict[str, Any] = {  # Any: JSON
            "iss": issuer,
            "sub": subject or user_id,
            "aud": resource or issuer,
            "client_id": client["client_id"],
            "scope": " ".join(scopes),
            "iat": int(now.timestamp()),
            "exp": int((now + access_ttl).timestamp()),
            "jti": row["id"],
        }
        if client.get("agent_id"):
            claims["act"] = {"sub": client["agent_id"]}
        response: dict[str, Any] = {  # Any: JSON
            "access_token": self.keys.sign(
                claims, kid=kid, alg=alg, key=key, typ="at+jwt"
            ),
            "token_type": "Bearer",
            "expires_in": int(access_ttl.total_seconds()),
            "scope": " ".join(scopes),
        }
        if refresh_token:
            response["refresh_token"] = refresh_token
        if "openid" in scopes and user_id is not None and subject is None:
            id_claims: dict[str, Any] = {  # Any: JSON
                "iss": issuer,
                "sub": user_id,
                "aud": client["client_id"],
                "iat": int(now.timestamp()),
                "exp": int((now + access_ttl).timestamp()),
                "auth_time": int(now.timestamp()),
                "jti": ctx.crypto.random_token(nbytes=16),
            }
            if nonce:
                id_claims["nonce"] = nonce
            response["id_token"] = self.keys.sign(
                id_claims, kid=kid, alg=alg, key=key, typ="JWT"
            )
        return response

    async def _revoke_family(self, ctx: EndpointContext, family_id: str) -> int:
        count = await ctx.adapter.update_many(
            "oauth_token",
            [Where("family_id", family_id), Where("revoked_at", True, "is_null")],
            {"revoked_at": ctx.clock.now()},
        )
        if count:
            await ctx.emit("oauth.token_revoked", family_id=family_id, count=count)
        return count

    # ------------------------------------------------------------ verification

    async def verify(
        self, ctx: EndpointContext, token: str, audiences: Sequence[str] | None
    ) -> Principal:
        """Check an access token and its grant row.

        Raises:
            TokenRejected: When the token must not be accepted.
        """
        claims = await self.keys.verify(
            ctx.adapter,
            ctx.clock.now(),
            token,
            typ="at+jwt",
            issuer=self.issuer(ctx),
            audiences=audiences,
        )
        row = await ctx.adapter.find_one(
            "oauth_token", [Where("id", str(claims["jti"]))]
        )
        if row is None or row.get("revoked_at") is not None:
            raise TokenRejected("revoked")
        client = await ctx.adapter.find_one(
            "oauth_client", [Where("client_id", row["client_id"])]
        )
        if client is None or client.get("disabled_at") is not None:
            raise TokenRejected("client disabled")
        agent_id = row.get("agent_id")
        if agent_id and "agent" in ctx.auth.schema:
            agent = await ctx.adapter.find_one("agent", [Where("id", agent_id)])
            if agent is None or agent.get("disabled_at") is not None:
                raise TokenRejected("agent disabled")
        return Principal(
            via="oauth_token",
            credential_id=row["id"],
            user_id=row.get("user_id"),
            agent_id=agent_id,
            client_id=row["client_id"],
            scopes=frozenset(str(claims.get("scope", "")).split()),
        )

    def local_audiences(self, ctx: EndpointContext) -> list[str]:
        """Audiences this app accepts as a resource server: the issuer and base_url."""
        return [self.issuer(ctx), ctx.auth.config.base_url.rstrip("/")]

    # ------------------------------------------------------------ other endpoints

    async def userinfo(self, ctx: EndpointContext, _: None) -> AuthResponse:
        header = ctx.request.headers.get("authorization", "")
        token = header[7:].strip() if header[:7].lower() == "bearer " else ""

        def challenge(error: str, status: int) -> AuthResponse:
            return AuthResponse(
                status=status,
                body={"error": error},
                headers={"www-authenticate": f'Bearer error="{error}"'},
            )

        try:
            principal = await self.verify(ctx, token, None)
        except TokenRejected:
            return challenge("invalid_token", 401)
        if not principal.has_scopes("openid") or principal.user_id is None:
            return challenge("insufficient_scope", 403)
        row = await ctx.adapter.find_one("user", [Where("id", principal.user_id)])
        if row is None:
            return challenge("invalid_token", 401)
        user = User.model_validate(returned_only(ctx.auth.schema["user"], row))
        claims: dict[str, Any] = {"sub": user.id}  # Any: JSON
        if principal.has_scopes("profile"):
            claims.update(name=user.name, picture=user.image)
        if principal.has_scopes("email"):
            claims.update(email=user.email, email_verified=user.email_verified)
        return AuthResponse(body=claims)

    async def introspect(
        self, ctx: EndpointContext, form: TokenRequestIn
    ) -> dict[str, Any]:  # Any: JSON
        await authenticate_client(
            ctx,
            self.clients,
            form.model_dump(exclude_none=True),
            require_confidential=True,
        )
        token = form.token or ""
        inactive: dict[str, Any] = {"active": False}  # Any: JSON
        if token.startswith(REFRESH_PREFIX):
            row = await ctx.adapter.find_one(
                "oauth_token",
                [Where("refresh_token_hash", ctx.crypto.hash_token(token))],
            )
            if (
                row is None
                or row.get("revoked_at") is not None
                or row["expires_at"] <= ctx.clock.now()
            ):
                return inactive
            return {
                "active": True,
                "token_type": "refresh_token",
                "client_id": row["client_id"],
                "scope": " ".join(row["scopes"]),
                "sub": row.get("user_id"),
                "exp": int(row["expires_at"].timestamp()),
            }
        try:
            claims = await self.keys.verify(
                ctx.adapter,
                ctx.clock.now(),
                token,
                typ="at+jwt",
                issuer=self.issuer(ctx),
                audiences=None,
            )
            await self.verify(ctx, token, None)
        except TokenRejected:
            return inactive
        return {
            "active": True,
            "token_type": "Bearer",
            "client_id": claims.get("client_id"),
            "scope": claims.get("scope"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
            "iss": claims.get("iss"),
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            **({"act": claims["act"]} if "act" in claims else {}),
        }

    async def revoke(
        self, ctx: EndpointContext, form: TokenRequestIn
    ) -> dict[str, Any]:  # Any: JSON
        client = await authenticate_client(
            ctx, self.clients, form.model_dump(exclude_none=True)
        )
        token = form.token or ""
        if token.startswith(REFRESH_PREFIX):
            row = await ctx.adapter.find_one(
                "oauth_token",
                [Where("refresh_token_hash", ctx.crypto.hash_token(token))],
            )
            if row is not None and row["client_id"] == client["client_id"]:
                await self._revoke_family(ctx, row["family_id"])
            return {}
        try:
            claims = await self.keys.verify(
                ctx.adapter,
                ctx.clock.now(),
                token,
                typ="at+jwt",
                issuer=self.issuer(ctx),
                audiences=None,
            )
        except TokenRejected:
            return {}  # RFC 7009: unknown tokens are not an error
        if claims.get("client_id") == client["client_id"]:
            count = await ctx.adapter.update_many(
                "oauth_token",
                [Where("id", str(claims["jti"])), Where("revoked_at", True, "is_null")],
                {"revoked_at": ctx.clock.now()},
            )
            if count:
                await ctx.emit(
                    "oauth.token_revoked", token_id=str(claims["jti"]), count=count
                )
        return {}

    async def jwks(self, ctx: EndpointContext, _: None) -> AuthResponse:
        await self.keys.ensure(ctx.adapter, ctx.crypto, ctx.clock, ctx.ids)
        return AuthResponse(
            body=await self.keys.jwks(ctx.adapter, ctx.clock.now()),
            headers={"cache-control": "public, max-age=300"},
        )

    async def discovery(self, ctx: EndpointContext, _: None) -> AuthResponse:
        return AuthResponse(
            body=self.metadata(ctx), headers={"cache-control": "public, max-age=300"}
        )
