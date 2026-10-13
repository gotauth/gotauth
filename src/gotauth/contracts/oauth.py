"""CONTRACTS sections 12.2-12.5: plugin models, endpoint ids, cross-plugin calls and the
MCP integration signatures for API keys (P1), the OAuth server (O1), agents (O3) and
organizations (P5)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel

from gotauth.contracts.endpoints import EndpointSpec
from gotauth.contracts.http_models import (
    CreateOAuthClientIn,
    CreateOAuthClientOut,
    HasPermissionIn,
    HasPermissionOut,
    IssueApiKeyIn,
    IssueApiKeyOut,
    RevokeAgentsIn,
    RevokeApiKeysIn,
    RevokedOut,
    RevokeOAuthTokensIn,
    UpdateOAuthClientIn,
    UpdateOAuthClientOut,
    VerifyAccessTokenIn,
    VerifyApiKeyIn,
    VerifyOut,
)
from gotauth.contracts.schema import Field, ModelSchema, Reference, Schema

if TYPE_CHECKING:
    from gotauth.contracts.config import GotAuthInstance

__all__ = [
    "AGENT_MODEL",
    "API_KEY_MODEL",
    "CROSS_PLUGIN_CALLS",
    "JWK_MODEL",
    "OAUTH_CLIENT_MODEL",
    "OAUTH_CODE_MODEL",
    "OAUTH_CONSENT_MODEL",
    "OAUTH_TOKEN_MODEL",
    "ORGANIZATION_STATEMENTS",
    "PLUGIN_ENDPOINTS",
    "PLUGIN_SCHEMA",
    "CrossPluginCall",
    "FastMCPAuthFactory",
    "MCPSDKAuthFactory",
    "ProtectedResourceMetadataFactory",
]

_USER_CASCADE = Reference("user", on_delete="cascade")
_USER_SET_NULL = Reference("user", on_delete="set_null")


def _fields(**fields: Field) -> Mapping[str, Field]:
    return MappingProxyType(fields)


# --- 12.2 models

API_KEY_MODEL = ModelSchema(
    name="api_key",
    fields=_fields(
        name=Field("string"),
        # First 6 characters after the prefix, for display.
        start=Field("string"),
        key_hash=Field("string", unique=True, returned=False),
        owner_type=Field("string"),  # "user" | "organization" | "agent"
        owner_id=Field("string", index=True),
        # The human the key acts for; deleting the user removes their keys.
        user_id=Field("string", required=False, references=_USER_CASCADE),
        scopes=Field("string_list"),
        expires_at=Field("datetime", required=False),
        last_used_at=Field("datetime", required=False),
        rate_limit_max=Field("integer", required=False),
        rate_limit_window=Field("integer", required=False),  # seconds
        enabled=Field("boolean", default=True),
        created_by=Field("string", required=False, references=_USER_SET_NULL),
        created_at=Field("datetime"),
        metadata=Field("json", default=dict),
    ),
)

AGENT_MODEL = ModelSchema(
    name="agent",
    fields=_fields(
        name=Field("string"),
        description=Field("string", required=False),
        owner_type=Field("string"),  # "user" | "organization"
        owner_id=Field("string", index=True),
        created_by=Field("string", required=False, references=_USER_SET_NULL),
        disabled_at=Field("datetime", required=False),
        created_at=Field("datetime"),
        metadata=Field("json", default=dict),
    ),
)

OAUTH_CLIENT_MODEL = ModelSchema(
    name="oauth_client",
    fields=_fields(
        # For CIMD clients, the metadata document URL.
        client_id=Field("string", unique=True),
        # Public clients have none; secrets use the "gcs_" prefix.
        client_secret_hash=Field("string", required=False, returned=False),
        type=Field("string"),  # "public" | "confidential"
        name=Field("string"),
        redirect_uris=Field("string_list"),
        grant_types=Field("string_list"),
        scopes=Field("string_list"),
        registration=Field("string"),  # "static" | "cimd" | "dynamic"
        agent_id=Field(
            "string",
            required=False,
            references=Reference("agent", on_delete="set_null"),
        ),
        owner_user_id=Field("string", required=False),
        disabled_at=Field("datetime", required=False),
        created_at=Field("datetime"),
    ),
)

OAUTH_CONSENT_MODEL = ModelSchema(
    name="oauth_consent",
    fields=_fields(
        user_id=Field("string", references=_USER_CASCADE),
        client_id=Field("string"),
        scopes=Field("string_list"),
        resource=Field("string", required=False),
        created_at=Field("datetime"),
    ),
)

OAUTH_CODE_MODEL = ModelSchema(
    name="oauth_code",
    fields=_fields(
        code_hash=Field("string", unique=True, returned=False),
        client_id=Field("string"),
        # A reference so deleting a user also removes pending codes (decision by F2).
        user_id=Field("string", references=_USER_CASCADE),
        redirect_uri=Field("string"),
        scopes=Field("string_list"),
        resource=Field("string", required=False),
        code_challenge=Field("string"),
        nonce=Field("string", required=False),
        # When the user signed in (the session's created_at), for the ID token.
        auth_time=Field("datetime", required=False),
        expires_at=Field("datetime"),  # now + 60s
    ),
)

OAUTH_TOKEN_MODEL = ModelSchema(
    name="oauth_token",
    fields=_fields(
        # client_credentials tokens have none.
        refresh_token_hash=Field("string", required=False, unique=True, returned=False),
        family_id=Field("string", index=True),
        parent_id=Field("string", required=False, references=Reference("oauth_token")),
        client_id=Field("string"),
        # A reference so deleting a user also removes their grants (decision by F2).
        user_id=Field("string", required=False, references=_USER_CASCADE),
        agent_id=Field("string", required=False),
        scopes=Field("string_list"),
        resource=Field("string", required=False),
        # Carried from the code through refreshes, for ID tokens (CCR 003).
        auth_time=Field("datetime", required=False),
        expires_at=Field("datetime"),
        revoked_at=Field("datetime", required=False),
        created_at=Field("datetime"),
    ),
)

JWK_MODEL = ModelSchema(
    name="jwk",
    fields=_fields(
        kid=Field("string", unique=True),
        alg=Field("string"),
        public_jwk=Field("json"),
        private_key_enc=Field("text", returned=False),  # purpose "jwk_private"
        created_at=Field("datetime"),
        retired_at=Field("datetime", required=False),
    ),
)

PLUGIN_SCHEMA: Schema = MappingProxyType(
    {
        model.name: model
        for model in (
            API_KEY_MODEL,
            AGENT_MODEL,
            OAUTH_CLIENT_MODEL,
            OAUTH_CONSENT_MODEL,
            OAUTH_CODE_MODEL,
            OAUTH_TOKEN_MODEL,
            JWK_MODEL,
        )
    }
)
"""The section 12.2 models by name. Each plugin adds only its own: P1 ``api_key``, O3
``agent``, O1 the ``oauth_*`` models and ``jwk``."""

# --- 12.3 endpoint ids


def _server_only(endpoint_id: str, owner: str) -> EndpointSpec:
    return EndpointSpec(endpoint_id, None, None, "none", owner, server_only=True)


PLUGIN_ENDPOINTS: tuple[EndpointSpec, ...] = (
    EndpointSpec("create_api_key", "POST", "/api-keys", "session", "P1"),
    EndpointSpec("list_api_keys", "GET", "/api-keys", "session", "P1"),
    EndpointSpec("update_api_key", "PATCH", "/api-keys/{id}", "session", "P1"),
    EndpointSpec("delete_api_key", "DELETE", "/api-keys/{id}", "session", "P1"),
    _server_only("verify_api_key", "P1"),
    _server_only("issue_api_key", "P1"),
    _server_only("revoke_api_keys", "P1"),
    EndpointSpec("oauth_authorize", "GET", "/oauth2/authorize", "optional", "O1"),
    EndpointSpec(
        "oauth_consent", "POST", "/oauth2/consent", "session", "O1", input_format="form"
    ),
    EndpointSpec(
        "oauth_token",
        "POST",
        "/oauth2/token",
        "none",
        "O1",
        input_format="form",
        error_format="oauth",
    ),
    EndpointSpec(
        "oauth_introspect",
        "POST",
        "/oauth2/introspect",
        "none",
        "O1",
        input_format="form",
        error_format="oauth",
    ),
    EndpointSpec(
        "oauth_revoke",
        "POST",
        "/oauth2/revoke",
        "none",
        "O1",
        input_format="form",
        error_format="oauth",
    ),
    EndpointSpec("oauth_jwks", "GET", "/oauth2/jwks", "none", "O1"),
    EndpointSpec("oauth_userinfo", "GET", "/oauth2/userinfo", "none", "O1"),
    EndpointSpec("oauth_register", "POST", "/oauth2/register", "none", "O1"),
    EndpointSpec(
        "oauth_openid_configuration",
        "GET",
        "/.well-known/openid-configuration",
        "none",
        "O1",
    ),
    EndpointSpec(
        "oauth_server_metadata",
        "GET",
        "/.well-known/oauth-authorization-server{base_path}",
        "none",
        "O1",
        well_known=True,
    ),
    EndpointSpec("list_oauth_grants", "GET", "/oauth2/grants", "session", "O1"),
    EndpointSpec(
        "revoke_oauth_grant", "POST", "/oauth2/grants/revoke", "session", "O1"
    ),
    _server_only("create_oauth_client", "O1"),
    _server_only("list_oauth_clients", "O1"),
    _server_only("get_oauth_client", "O1"),
    _server_only("update_oauth_client", "O1"),
    _server_only("delete_oauth_client", "O1"),
    _server_only("rotate_oauth_client_secret", "O1"),
    _server_only("rotate_signing_key", "O1"),
    _server_only("revoke_oauth_tokens", "O1"),
    _server_only("verify_access_token", "O1"),
    EndpointSpec("create_agent", "POST", "/agents", "session", "O3"),
    EndpointSpec("list_agents", "GET", "/agents", "session", "O3"),
    EndpointSpec("get_agent", "GET", "/agents/{id}", "session", "O3"),
    EndpointSpec("update_agent", "PATCH", "/agents/{id}", "session", "O3"),
    EndpointSpec("revoke_agent", "POST", "/agents/{id}/revoke", "session", "O3"),
    EndpointSpec(
        "create_agent_api_key", "POST", "/agents/{id}/api-keys", "session", "O3"
    ),
    EndpointSpec(
        "list_agent_api_keys", "GET", "/agents/{id}/api-keys", "session", "O3"
    ),
    EndpointSpec("link_oauth_client", "POST", "/agents/{id}/clients", "session", "O3"),
    _server_only("revoke_agents", "O3"),
    EndpointSpec(
        "has_permission",
        "POST",
        "/organization/has-permission",
        "principal",
        "P5",
        output=(HasPermissionOut,),
    ),
)
"""The section 12.3 endpoint ids, including P5's ``has_permission``. Server-only rows
have no fixed method and path; their owners choose them."""

ORGANIZATION_STATEMENTS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "organization": ("update", "delete"),
        "member": ("create", "update", "delete"),
        "invitation": ("create", "cancel"),
        "api_key": ("create", "read", "update", "revoke"),
        "agent": ("create", "read", "update", "revoke"),
    }
)
"""P5's built-in permission statements: resource -> actions (12.3)."""

# --- 12.5 cross-plugin calls


@dataclass(frozen=True)
class CrossPluginCall:
    """One row of the section 12.5 table.

    Attributes:
        id: Endpoint id, called as ``ctx.auth.api.call(id, body=..., ctx=ctx)``.
        owner: Owning work package.
        input: The exact input shape.
        output: The exact output shape.
    """

    id: str
    owner: str
    input: type[BaseModel]
    output: type[BaseModel]


CROSS_PLUGIN_CALLS: Mapping[str, CrossPluginCall] = MappingProxyType(
    {
        call.id: call
        for call in (
            CrossPluginCall("issue_api_key", "P1", IssueApiKeyIn, IssueApiKeyOut),
            CrossPluginCall("revoke_api_keys", "P1", RevokeApiKeysIn, RevokedOut),
            CrossPluginCall("verify_api_key", "P1", VerifyApiKeyIn, VerifyOut),
            CrossPluginCall(
                "create_oauth_client", "O1", CreateOAuthClientIn, CreateOAuthClientOut
            ),
            CrossPluginCall(
                "update_oauth_client", "O1", UpdateOAuthClientIn, UpdateOAuthClientOut
            ),
            CrossPluginCall(
                "revoke_oauth_tokens", "O1", RevokeOAuthTokensIn, RevokedOut
            ),
            CrossPluginCall(
                "verify_access_token", "O1", VerifyAccessTokenIn, VerifyOut
            ),
            CrossPluginCall("revoke_agents", "O3", RevokeAgentsIn, RevokedOut),
            CrossPluginCall("has_permission", "P5", HasPermissionIn, HasPermissionOut),
        )
    }
)
"""The frozen cross-plugin shapes of section 12.5, by endpoint id."""

# --- 12.4 MCP surface


class FastMCPAuthFactory(Protocol):
    """Signature of ``gotauth.integrations.mcp.fastmcp_auth`` (O2).

    Returns a FastMCP auth provider that verifies GotAuth access tokens and advertises
    the authorization server in RFC 9728 metadata. ``introspect=True`` without
    ``introspection_client`` raises ``ConfigError``.

    ``WWW-Authenticate`` challenges (MCP 2026-07-28), built or checked by GotAuth:

    - no token: 401
      ``Bearer resource_metadata="<url>", scope="<scopes>"``
      (``scope`` omitted when empty)
    - bad or expired token: 401
      ``Bearer error="invalid_token", resource_metadata="<url>", scope="<scopes>"``
    - missing scope: 403
      ``Bearer error="insufficient_scope", scope="<needed>", resource_metadata="<url>"``
      where ``<needed>`` is every scope the call needs

    ``<scopes>`` is the ``scopes`` argument, space-separated, without
    ``offline_access``.
    """

    def __call__(
        self,
        auth: GotAuthInstance | None = None,
        *,
        issuer: str | None = None,
        resource: str,
        scopes: Sequence[str] = (),
        introspect: bool = False,
        introspection_client: tuple[str, str] | None = None,
    ) -> Any:  # Any: a FastMCP auth provider; contracts cannot import FastMCP
        """Build the provider."""
        ...


class MCPSDKAuthFactory(Protocol):
    """Signature of ``gotauth.integrations.mcp.mcp_sdk_auth`` (O2).

    Returns ``(AuthSettings, TokenVerifier)`` for the MCP Python SDK, with the same
    challenges as :class:`FastMCPAuthFactory`.
    """

    def __call__(
        self,
        auth: GotAuthInstance | None = None,
        *,
        issuer: str | None = None,
        resource: str,
        scopes: Sequence[str] = (),
        introspect: bool = False,
        introspection_client: tuple[str, str] | None = None,
    ) -> tuple[Any, Any]:  # Any: MCP SDK types; contracts cannot import the SDK
        """Build the settings and verifier."""
        ...


class ProtectedResourceMetadataFactory(Protocol):
    """Signature of ``gotauth.integrations.mcp.protected_resource_metadata`` (O2).

    ``scopes_supported`` never contains ``offline_access``.
    """

    def __call__(
        self, *, resource: str, issuer: str, scopes: Sequence[str]
    ) -> dict[str, Any]:  # Any: a JSON document
        """Return the RFC 9728 metadata document."""
        ...
