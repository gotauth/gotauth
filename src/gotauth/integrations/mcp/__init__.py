"""MCP integration for FastMCP and the official MCP Python SDK (work package O2).

Protect an MCP server with GotAuth access tokens: the server verifies them,
advertises GotAuth as its authorization server (RFC 9728) and gives tools the user,
agent and scopes (CONTRACTS 12.4). Needs ``pip install "gotauth[mcp]"``::

    from fastmcp import FastMCP
    from fastmcp.server.auth import require_scopes

    from gotauth.integrations.mcp import current_access, fastmcp_auth

    mcp = FastMCP(
        "projects",
        auth=fastmcp_auth(auth, resource="https://api.example.com/mcp",
                          scopes=["projects:read"]),
    )

    @mcp.tool(auth=require_scopes("projects:write"))
    def create_project(name: str) -> str:
        access = current_access()
        ...
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from gotauth.integrations.mcp._access import GotAuthAccess, current_access
from gotauth.integrations.mcp._metadata import protected_resource_metadata
from gotauth.integrations.mcp._verify import build_verifier

if TYPE_CHECKING:
    from gotauth.contracts.config import GotAuthInstance

__all__ = [
    "GotAuthAccess",
    "current_access",
    "fastmcp_auth",
    "mcp_sdk_auth",
    "protected_resource_metadata",
]


def fastmcp_auth(
    auth: GotAuthInstance | None = None,
    *,
    issuer: str | None = None,
    resource: str,
    scopes: Sequence[str] = (),
    introspect: bool = False,
    introspection_client: tuple[str, str] | None = None,
) -> Any:  # Any: a FastMCP AuthProvider; FastMCP is an optional extra
    """A FastMCP auth provider that accepts GotAuth access tokens.

    Args:
        auth: The GotAuth with the ``oauth_provider`` plugin, in the same process.
            Revocation then takes effect on the next call.
        issuer: Instead of ``auth``: the issuer URL of a GotAuth in another process.
            Tokens are checked against its JWKS, so a revoked token works until it
            expires, unless ``introspect`` is on.
        resource: The MCP server's URL; tokens must name it in ``aud``.
        scopes: Scopes every call needs; ``offline_access`` is ignored.
        introspect: With ``issuer``, also ask the issuer's introspection endpoint
            (results cached for 5 seconds), so revocation is seen at once.
        introspection_client: ``(client_id, client_secret)`` of a confidential client,
            for ``introspect``.

    Returns:
        A ``RemoteAuthProvider`` for ``FastMCP(auth=...)``.

    Raises:
        ConfigError: Unless exactly one of ``auth`` and ``issuer`` is given, for a bad
            ``resource``, without the plugin, or for ``introspect`` without a client.
    """
    from gotauth.integrations.mcp._fastmcp import GotAuthProvider

    verifier = build_verifier(
        auth,
        issuer=issuer,
        resource=resource,
        introspect=introspect,
        introspection_client=introspection_client,
    )
    return GotAuthProvider(verifier, scopes)


def mcp_sdk_auth(
    auth: GotAuthInstance | None = None,
    *,
    issuer: str | None = None,
    resource: str,
    scopes: Sequence[str] = (),
    introspect: bool = False,
    introspection_client: tuple[str, str] | None = None,
) -> tuple[Any, Any]:  # Any: the SDK's AuthSettings and TokenVerifier
    """``(AuthSettings, TokenVerifier)`` for the official MCP SDK's ``MCPServer``.

    Same arguments as :func:`fastmcp_auth`. Wrap the server's app with
    ``verifier.guard(app)`` for the spec-correct 401 and 403 challenges.

    Raises:
        ConfigError: As :func:`fastmcp_auth`.
    """
    from gotauth.integrations.mcp._sdk import GotAuthTokenVerifier, auth_settings

    verifier = build_verifier(
        auth,
        issuer=issuer,
        resource=resource,
        introspect=introspect,
        introspection_client=introspection_client,
    )
    return auth_settings(verifier, scopes), GotAuthTokenVerifier(verifier, scopes)
