"""The ``oauth_provider`` plugin: endpoints, server-only management and the resolver."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict

from gotauth.contracts.adapter import Where
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError, ConfigError
from gotauth.contracts.http import AuthResponse
from gotauth.contracts.http_models import (
    CreateOAuthClientIn,
    CreateOAuthClientOut,
    OAuthClientOut,
    RevokedOut,
    RevokeOAuthTokensIn,
    StatusOut,
    UpdateOAuthClientIn,
    UpdateOAuthClientOut,
    VerifyAccessTokenIn,
    VerifyOut,
)
from gotauth.contracts.oauth import (
    JWK_MODEL,
    OAUTH_CLIENT_MODEL,
    OAUTH_CODE_MODEL,
    OAUTH_CONSENT_MODEL,
    OAUTH_TOKEN_MODEL,
)
from gotauth.contracts.primitives import Duration
from gotauth.contracts.principal import Principal
from gotauth.contracts.schema import returned_only
from gotauth.contracts.sessions import TOKEN_PREFIXES, is_localhost

from ._keys import PrincipalRefused, TokenRejected
from ._rules import (
    Settings,
    is_loopback_redirect,
    normalize_resource,
    valid_redirect_uri,
)
from ._server import (
    AuthorizeIn,
    ConsentIdIn,
    ConsentIn,
    OAuthConsentOut,
    OAuthServer,
    TokenIn,
    TokenRequestIn,
)

if TYPE_CHECKING:
    from gotauth.contracts.config import GotAuthInstance

__all__ = ["OAuthJwtResolver", "oauth_provider"]

SECRET_PREFIX = TOKEN_PREFIXES["oauth_client_secret"]
_GRANTS = {"authorization_code", "refresh_token", "client_credentials"}

ERROR_CODES: dict[str, tuple[int, str]] = {
    "OAUTH_INVALID_REQUEST": (400, "invalid_request"),
    "OAUTH_INVALID_CLIENT": (401, "invalid_client"),
    "OAUTH_INVALID_GRANT": (400, "invalid_grant"),
    "OAUTH_UNAUTHORIZED_CLIENT": (400, "unauthorized_client"),
    "OAUTH_UNSUPPORTED_GRANT_TYPE": (400, "unsupported_grant_type"),
    "OAUTH_INVALID_SCOPE": (400, "invalid_scope"),
    "OAUTH_INVALID_TARGET": (400, "invalid_target"),
}


class ClientIdIn(BaseModel):
    """Input of the server-only calls that name one client."""

    model_config = ConfigDict(extra="forbid")

    client_id: str


class ListOAuthClientsIn(BaseModel):
    """``list_oauth_clients`` filters."""

    model_config = ConfigDict(extra="forbid")

    owner_user_id: str | None = None
    agent_id: str | None = None


class OAuthClientListOut(BaseModel):
    """``list_oauth_clients`` output."""

    clients: list[OAuthClientOut]


class OAuthGrantOut(BaseModel):
    """An app the signed-in user authorized: a client with a stored consent or live
    tokens for the user."""

    client_id: str
    client_name: str
    scopes: list[str]
    resources: list[str]
    created_at: datetime
    last_used_at: datetime | None
    """When the client last got tokens (sign-in or refresh), if it holds any."""


class OAuthGrantListOut(BaseModel):
    """``list_oauth_grants`` output."""

    grants: list[OAuthGrantOut]


class SigningKeyOut(BaseModel):
    """``rotate_signing_key`` output."""

    kid: str


class RegisterIn(BaseModel):
    """RFC 7591 registration request (public clients only)."""

    model_config = ConfigDict(extra="ignore")

    redirect_uris: list[str]
    client_name: str | None = None
    application_type: Literal["native", "web"] | None = None
    grant_types: list[str] | None = None
    token_endpoint_auth_method: str | None = None
    scope: str | None = None


def _client_out(
    ctx: EndpointContext, row: dict[str, Any]
) -> OAuthClientOut:  # Any: row
    return OAuthClientOut.model_validate(
        returned_only(ctx.auth.schema["oauth_client"], row)
    )


class OAuthJwtResolver:
    """Resolves ``eyJ`` access tokens issued for this app (``aud`` = issuer or
    ``base_url``); revoked tokens and disabled clients or agents never resolve."""

    prefixes: tuple[str, ...] = ("eyJ",)

    def __init__(self, server: OAuthServer) -> None:
        self._server = server

    async def __call__(self, ctx: EndpointContext, credential: str) -> Principal | None:
        try:
            return await self._server.verify(
                ctx, credential, self._server.local_audiences(ctx), owner_only=True
            )
        except PrincipalRefused as refused:
            # The client's owner, whom the pipeline's own checks never see: the
            # check's own error (ADMIN_USER_BANNED), not a plain 401.
            raise refused.error from None
        except TokenRejected:
            return None


def oauth_provider(
    *,
    login_page: str = "/sign-in",
    consent_page: str | None = None,
    scopes: Sequence[str] = ("openid", "profile", "email", "offline_access"),
    resources: Sequence[str] = (),
    access_token_ttl: Duration = "10m",  # noqa: S107 - a duration, not a password
    refresh_token_ttl: Duration = "30d",  # noqa: S107
    signing_alg: str = "ES256",
    allow_cimd: bool = True,
    allow_dynamic_registration: bool = False,
    mcp: bool = False,
) -> Plugin:
    """Return the ``oauth_provider`` plugin: an OAuth 2.1 server and OIDC provider.

    Args:
        login_page: Where the browser signs in; gets ``?callback_url=<authorize URL>``.
        consent_page: Your own consent page (gets ``?consent_id=...``); default is
            GotAuth's built-in page.
        scopes: Scopes clients may ask for.
        resources: Allowed audiences (RFC 8707) besides the issuer, e.g. MCP servers.
        access_token_ttl: Access token lifetime.
        refresh_token_ttl: Refresh grant lifetime.
        signing_alg: ``"ES256"`` (default) or ``"RS256"``.
        allow_cimd: Accept client ID metadata documents (https URL client ids).
        allow_dynamic_registration: Serve RFC 7591 registration (public clients).
        mcp: MCP mode: ``resource`` is required and ``base_url`` must be https
            (or a loopback host for local development).

    Raises:
        ConfigError: Invalid options; with ``mcp=True``, a non-https ``base_url`` on
            first use.
    """
    settings = Settings(
        login_page=login_page,
        consent_page=consent_page,
        scopes=tuple(scopes),
        resources=tuple(resources),
        access_token_ttl=access_token_ttl,
        refresh_token_ttl=refresh_token_ttl,
        signing_alg=signing_alg,
        allow_cimd=allow_cimd,
        allow_dynamic_registration=allow_dynamic_registration,
        mcp=mcp,
    )
    server = OAuthServer(settings)

    async def init(auth: GotAuthInstance) -> None:
        if mcp:
            base_url = auth.config.base_url
            if not base_url.startswith("https://") and not is_localhost(base_url):
                msg = "oauth_provider(mcp=True) needs an https (or loopback) base_url"
                raise ConfigError(msg)

    # -------------------------------------------------------- client management

    def check_redirects(uris: Sequence[str]) -> list[str]:
        if not uris or not all(valid_redirect_uri(uri) for uri in uris):
            raise AuthError(
                "INVALID_REQUEST",
                400,
                "redirect_uris must be https or loopback http, without fragments",
            )
        return list(uris)

    def check_scopes(requested: Sequence[str] | None) -> list[str]:
        values = list(requested) if requested is not None else list(settings.scopes)
        if not set(values) <= set(settings.scopes):
            raise AuthError("INVALID_REQUEST", 400, "Unknown scopes")
        return sorted(set(values))

    async def find_client(
        ctx: EndpointContext, client_id: str
    ) -> dict[str, Any]:  # Any: row
        row = await ctx.adapter.find_one(
            "oauth_client", [Where("client_id", client_id)]
        )
        if row is None:
            raise AuthError("NOT_FOUND", 404)
        return row

    async def create_client(
        ctx: EndpointContext, body: CreateOAuthClientIn
    ) -> CreateOAuthClientOut:
        grants = body.grant_types or ["authorization_code", "refresh_token"]
        if not set(grants) <= _GRANTS:
            raise AuthError("INVALID_REQUEST", 400, "Unknown grant types")
        if "client_credentials" in grants and body.type != "confidential":
            raise AuthError(
                "INVALID_REQUEST", 400, "client_credentials needs a confidential client"
            )
        uses_redirects = bool(set(grants) & {"authorization_code"})
        redirects = (
            check_redirects(body.redirect_uris)
            if uses_redirects or body.redirect_uris
            else []
        )
        secret = (
            ctx.crypto.random_token(SECRET_PREFIX)
            if body.type == "confidential"
            else None
        )
        client_row_id = ctx.ids.new("cli")
        row = await ctx.adapter.create(
            "oauth_client",
            {
                "id": client_row_id,
                "client_id": client_row_id,
                "client_secret_hash": ctx.crypto.hash_token(secret) if secret else None,
                "type": body.type,
                "name": body.name,
                "redirect_uris": redirects,
                "grant_types": sorted(set(grants)),
                "scopes": check_scopes(body.scopes),
                "registration": "static",
                "agent_id": body.agent_id,
                "owner_user_id": body.owner_user_id,
                "created_at": ctx.clock.now(),
            },
        )
        await ctx.emit(
            "oauth.client_created",
            client_id=row["client_id"],
            user_id=body.owner_user_id,
        )
        return CreateOAuthClientOut(client=_client_out(ctx, row), client_secret=secret)

    async def list_clients(
        ctx: EndpointContext, body: ListOAuthClientsIn
    ) -> OAuthClientListOut:
        where: list[Where] = []
        if body.owner_user_id is not None:
            where.append(Where("owner_user_id", body.owner_user_id))
        if body.agent_id is not None:
            where.append(Where("agent_id", body.agent_id))
        rows = await ctx.adapter.find_many("oauth_client", where)
        return OAuthClientListOut(clients=[_client_out(ctx, row) for row in rows])

    async def get_client(
        ctx: EndpointContext, body: ClientIdIn
    ) -> UpdateOAuthClientOut:
        return UpdateOAuthClientOut(
            client=_client_out(ctx, await find_client(ctx, body.client_id))
        )

    async def update_client(
        ctx: EndpointContext, body: UpdateOAuthClientIn
    ) -> UpdateOAuthClientOut:
        row = await find_client(ctx, body.client_id)
        changes: dict[str, Any] = {}  # Any: field values
        given = body.model_fields_set
        if "name" in given and body.name is not None:
            changes["name"] = body.name
        if "redirect_uris" in given and body.redirect_uris is not None:
            changes["redirect_uris"] = check_redirects(body.redirect_uris)
        if "scopes" in given and body.scopes is not None:
            changes["scopes"] = check_scopes(body.scopes)
        if "agent_id" in given:
            changes["agent_id"] = body.agent_id  # an explicit null unlinks
        if "disabled" in given and body.disabled is not None:
            changes["disabled_at"] = ctx.clock.now() if body.disabled else None
        updated = row
        if changes:
            updated = (
                await ctx.adapter.update(
                    "oauth_client", [Where("id", row["id"])], changes
                )
                or row
            )
        return UpdateOAuthClientOut(client=_client_out(ctx, updated))

    async def delete_client(ctx: EndpointContext, body: ClientIdIn) -> StatusOut:
        row = await find_client(ctx, body.client_id)
        await ctx.adapter.update_many(
            "oauth_token",
            [
                Where("client_id", row["client_id"]),
                Where("revoked_at", True, "is_null"),
            ],
            {"revoked_at": ctx.clock.now()},
        )
        await ctx.adapter.delete(
            "oauth_consent", [Where("client_id", row["client_id"])]
        )
        await ctx.adapter.delete("oauth_code", [Where("client_id", row["client_id"])])
        await ctx.adapter.delete("oauth_client", [Where("id", row["id"])])
        return StatusOut(status="ok")

    async def rotate_secret(
        ctx: EndpointContext, body: ClientIdIn
    ) -> CreateOAuthClientOut:
        row = await find_client(ctx, body.client_id)
        if row["type"] != "confidential":
            raise AuthError("INVALID_REQUEST", 400, "Public clients have no secret")
        secret = ctx.crypto.random_token(SECRET_PREFIX)
        updated = await ctx.adapter.update(
            "oauth_client",
            [Where("id", row["id"])],
            {"client_secret_hash": ctx.crypto.hash_token(secret)},
        )
        return CreateOAuthClientOut(
            client=_client_out(ctx, updated or row), client_secret=secret
        )

    async def rotate_key(ctx: EndpointContext, _: None) -> SigningKeyOut:
        row = await server.keys.create(ctx.adapter, ctx.crypto, ctx.clock, ctx.ids)
        return SigningKeyOut(kid=str(row["kid"]))

    async def revoke_tokens(
        ctx: EndpointContext, body: RevokeOAuthTokensIn
    ) -> RevokedOut:
        where = [Where("revoked_at", True, "is_null")]
        for name in ("client_id", "user_id", "agent_id", "family_id"):
            value = getattr(body, name)
            if value is not None:
                where.append(Where(name, value))
        count = await ctx.adapter.update_many(
            "oauth_token", where, {"revoked_at": ctx.clock.now()}
        )
        if count:
            await ctx.emit(
                "oauth.token_revoked", count=count, **body.model_dump(exclude_none=True)
            )
        return RevokedOut(revoked=count)

    # -------------------------------------------------------- the user's grants

    def grant_owner(ctx: EndpointContext) -> str:
        principal = ctx.principal
        if principal is None or principal.user_id is None:  # the pipeline checked
            raise AuthError("UNAUTHENTICATED", 401)
        return principal.user_id

    async def list_grants(ctx: EndpointContext, _: None) -> OAuthGrantListOut:
        user_id = grant_owner(ctx)
        consents = await ctx.adapter.find_many(
            "oauth_consent", [Where("user_id", user_id)]
        )
        tokens = await ctx.adapter.find_many(
            "oauth_token",
            [
                Where("user_id", user_id),
                Where("revoked_at", True, "is_null"),
                Where("expires_at", ctx.clock.now(), "gt"),
            ],
        )
        found: dict[str, dict[str, Any]] = {}  # Any: the grant being built
        for row in (*consents, *tokens):
            grant = found.setdefault(
                row["client_id"],
                {
                    "scopes": set[str](),
                    "resources": set[str](),
                    "created_at": row["created_at"],
                    "last_used_at": None,
                },
            )
            grant["scopes"].update(row["scopes"])
            if row.get("resource"):
                grant["resources"].add(row["resource"])
            grant["created_at"] = min(grant["created_at"], row["created_at"])
        for row in tokens:
            grant = found[row["client_id"]]
            last = grant["last_used_at"]
            grant["last_used_at"] = (
                row["created_at"] if last is None else max(last, row["created_at"])
            )
        clients = (
            await ctx.adapter.find_many(
                "oauth_client", [Where("client_id", list(found), "in")]
            )
            if found
            else []
        )
        names = {row["client_id"]: row["name"] for row in clients}
        grants = [
            OAuthGrantOut(
                client_id=client_id,
                client_name=names.get(client_id, client_id),
                scopes=sorted(grant["scopes"]),
                resources=sorted(grant["resources"]),
                created_at=grant["created_at"],
                last_used_at=grant["last_used_at"],
            )
            for client_id, grant in found.items()
        ]
        grants.sort(key=lambda grant: (grant.created_at, grant.client_id))
        return OAuthGrantListOut(grants=grants)

    async def revoke_grant(ctx: EndpointContext, body: ClientIdIn) -> RevokedOut:
        # The consent, unused codes and every token of this client for this user.
        # Access tokens check their row, so they stop working at once. Revoking a
        # grant the user does not have is a no-op, not an error.
        user_id = grant_owner(ctx)
        owned = [Where("user_id", user_id), Where("client_id", body.client_id)]
        await ctx.adapter.delete("oauth_consent", owned)
        await ctx.adapter.delete("oauth_code", owned)
        count = await ctx.adapter.update_many(
            "oauth_token",
            [*owned, Where("revoked_at", True, "is_null")],
            {"revoked_at": ctx.clock.now()},
        )
        if count:
            await ctx.emit(
                "oauth.token_revoked",
                count=count,
                client_id=body.client_id,
                user_id=user_id,
            )
        return RevokedOut(revoked=count)

    async def verify_token(
        ctx: EndpointContext, body: VerifyAccessTokenIn
    ) -> VerifyOut:
        if body.resource is not None:
            audience = normalize_resource(body.resource)
            if audience is None:
                return VerifyOut(valid=False, code="invalid_target")
            audiences = [audience]
        else:
            audiences = [server.issuer(ctx)]
        try:
            principal = await server.verify(ctx, body.token, audiences)
        except PrincipalRefused as refused:
            return VerifyOut(valid=False, code=refused.code)
        except TokenRejected:
            return VerifyOut(valid=False, code="invalid_token")
        if body.scopes and not principal.has_scopes(*body.scopes):
            return VerifyOut(valid=False, code="insufficient_scope")
        return VerifyOut(valid=True, principal=principal)

    # -------------------------------------------------------- dynamic registration

    async def register(ctx: EndpointContext, body: RegisterIn) -> AuthResponse:
        def invalid(error: str, description: str) -> AuthResponse:
            return AuthResponse(
                status=400, body={"error": error, "error_description": description}
            )

        if body.application_type is None:
            return invalid("invalid_client_metadata", "application_type is required")
        if body.token_endpoint_auth_method not in (None, "none"):
            return invalid(
                "invalid_client_metadata", "only public clients can register"
            )
        grants = body.grant_types or ["authorization_code", "refresh_token"]
        if not set(grants) <= {"authorization_code", "refresh_token"}:
            return invalid("invalid_client_metadata", "unsupported grant_types")
        uris = body.redirect_uris
        if not uris or not all(valid_redirect_uri(uri) for uri in uris):
            return invalid(
                "invalid_redirect_uri", "redirect_uris break the redirect rule"
            )
        loopback = [is_loopback_redirect(uri) for uri in uris]
        if body.application_type == "native" and not all(loopback):
            return invalid(
                "invalid_redirect_uri", "native clients use loopback redirects"
            )
        if body.application_type == "web" and any(loopback):
            return invalid("invalid_redirect_uri", "web clients use https redirects")
        requested = (body.scope or "").split()
        if not set(requested) <= set(settings.scopes):
            return invalid("invalid_client_metadata", "unknown scope")
        # Like a CIMD client, a registered public client may ask for any configured
        # scope later: MCP clients register with the first scope they see, then
        # step up (403 insufficient_scope). The user consents to each scope anyway.
        client_row_id = ctx.ids.new("cli")
        now = ctx.clock.now()
        row = await ctx.adapter.create(
            "oauth_client",
            {
                "id": client_row_id,
                "client_id": client_row_id,
                "type": "public",
                "name": body.client_name or "Unnamed client",
                "redirect_uris": list(uris),
                "grant_types": sorted(set(grants)),
                "scopes": list(settings.scopes),
                "registration": "dynamic",
                "created_at": now,
            },
        )
        await ctx.emit("oauth.client_created", client_id=row["client_id"])
        return AuthResponse(
            status=201,
            body={
                "client_id": row["client_id"],
                "client_id_issued_at": int(now.timestamp()),
                "client_name": row["name"],
                "redirect_uris": row["redirect_uris"],
                "grant_types": row["grant_types"],
                "token_endpoint_auth_method": "none",
                "application_type": body.application_type,
                "scope": " ".join(row["scopes"]),
            },
        )

    # -------------------------------------------------------- endpoints

    tags = ("oauth",)
    endpoints: list[Endpoint[Any, Any]] = [
        Endpoint(
            "oauth_authorize",
            "GET",
            "/oauth2/authorize",
            server.authorize,
            input=AuthorizeIn,
            auth="optional",
            summary="OAuth 2.1 authorization endpoint",
            tags=tags,
        ),
        Endpoint(
            "oauth_consent",
            "POST",
            "/oauth2/consent",
            server.consent,
            input=ConsentIn,
            input_format="form",
            auth="session",
            summary="Approve or deny a consent request",
            tags=tags,
        ),
        Endpoint(
            "get_oauth_consent",
            "GET",
            "/oauth2/consent",
            server.consent_details,
            input=ConsentIdIn,
            output=OAuthConsentOut,
            auth="session",
            summary="What a consent request asks for (for your own consent page)",
            tags=tags,
        ),
        Endpoint(
            "oauth_token",
            "POST",
            "/oauth2/token",
            server.token,
            input=TokenIn,
            input_format="form",
            error_format="oauth",
            summary="OAuth 2.1 token endpoint",
            tags=tags,
        ),
        Endpoint(
            "oauth_introspect",
            "POST",
            "/oauth2/introspect",
            server.introspect,
            input=TokenRequestIn,
            input_format="form",
            error_format="oauth",
            summary="Token introspection (RFC 7662)",
            tags=tags,
        ),
        Endpoint(
            "oauth_revoke",
            "POST",
            "/oauth2/revoke",
            server.revoke,
            input=TokenRequestIn,
            input_format="form",
            error_format="oauth",
            summary="Token revocation (RFC 7009)",
            tags=tags,
        ),
        Endpoint(
            "oauth_jwks",
            "GET",
            "/oauth2/jwks",
            server.jwks,
            summary="Signing keys (JWKS)",
            tags=tags,
        ),
        Endpoint(
            "oauth_userinfo",
            "GET",
            "/oauth2/userinfo",
            server.userinfo,
            summary="OpenID Connect userinfo",
            tags=tags,
        ),
        Endpoint(
            "oauth_openid_configuration",
            "GET",
            "/.well-known/openid-configuration",
            server.discovery,
            summary="OpenID provider metadata",
            tags=tags,
        ),
        Endpoint(
            "list_oauth_grants",
            "GET",
            "/oauth2/grants",
            list_grants,
            output=OAuthGrantListOut,
            auth="session",
            summary="Apps the signed-in user has authorized",
            tags=tags,
        ),
        Endpoint(
            "revoke_oauth_grant",
            "POST",
            "/oauth2/grants/revoke",
            revoke_grant,
            input=ClientIdIn,
            output=RevokedOut,
            auth="session",
            summary="Revoke an app's access: its consent and tokens",
            tags=tags,
        ),
        Endpoint(
            "create_oauth_client",
            "POST",
            "/oauth2/clients",
            create_client,
            input=CreateOAuthClientIn,
            output=CreateOAuthClientOut,
            server_only=True,
        ),
        Endpoint(
            "list_oauth_clients",
            "POST",
            "/oauth2/clients/list",
            list_clients,
            input=ListOAuthClientsIn,
            output=OAuthClientListOut,
            server_only=True,
        ),
        Endpoint(
            "get_oauth_client",
            "POST",
            "/oauth2/clients/get",
            get_client,
            input=ClientIdIn,
            output=UpdateOAuthClientOut,
            server_only=True,
        ),
        Endpoint(
            "update_oauth_client",
            "POST",
            "/oauth2/clients/update",
            update_client,
            input=UpdateOAuthClientIn,
            output=UpdateOAuthClientOut,
            server_only=True,
        ),
        Endpoint(
            "delete_oauth_client",
            "POST",
            "/oauth2/clients/delete",
            delete_client,
            input=ClientIdIn,
            output=StatusOut,
            server_only=True,
        ),
        Endpoint(
            "rotate_oauth_client_secret",
            "POST",
            "/oauth2/clients/rotate-secret",
            rotate_secret,
            input=ClientIdIn,
            output=CreateOAuthClientOut,
            server_only=True,
        ),
        Endpoint(
            "rotate_signing_key",
            "POST",
            "/oauth2/keys/rotate",
            rotate_key,
            output=SigningKeyOut,
            server_only=True,
        ),
        Endpoint(
            "revoke_oauth_tokens",
            "POST",
            "/oauth2/tokens/revoke",
            revoke_tokens,
            input=RevokeOAuthTokensIn,
            output=RevokedOut,
            server_only=True,
        ),
        Endpoint(
            "verify_access_token",
            "POST",
            "/oauth2/tokens/verify",
            verify_token,
            input=VerifyAccessTokenIn,
            output=VerifyOut,
            server_only=True,
        ),
    ]
    if allow_dynamic_registration:
        endpoints.append(
            Endpoint(
                "oauth_register",
                "POST",
                "/oauth2/register",
                register,
                input=RegisterIn,
                summary="Dynamic client registration (RFC 7591)",
                tags=tags,
            )
        )
    return Plugin(
        id="oauth_provider",
        schema={
            model.name: model
            for model in (
                OAUTH_CLIENT_MODEL,
                OAUTH_CONSENT_MODEL,
                OAUTH_CODE_MODEL,
                OAUTH_TOKEN_MODEL,
                JWK_MODEL,
            )
        },
        endpoints=tuple(endpoints),
        well_known_endpoints=(
            Endpoint(
                "oauth_server_metadata",
                "GET",
                "/.well-known/oauth-authorization-server{base_path}",
                server.discovery,
                summary="OAuth authorization server metadata (RFC 8414)",
                tags=tags,
            ),
        ),
        principal_resolvers=(OAuthJwtResolver(server),),
        error_codes=ERROR_CODES,
        init=init,
    )
