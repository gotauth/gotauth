"""The official MCP Python SDK (needs ``pip install "gotauth[mcp]"``)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

from gotauth.integrations.mcp._access import CLAIMS_KEY
from gotauth.integrations.mcp._guard import App, McpGuard, Scope, verified_in_request
from gotauth.integrations.mcp._metadata import advertised_scopes
from gotauth.integrations.mcp._verify import Verified, Verifier

__all__ = ["GotAuthTokenVerifier", "auth_settings"]


def auth_settings(verifier: Verifier, scopes: Sequence[str]) -> AuthSettings:
    """The SDK's resource-server settings for a GotAuth issuer."""
    return AuthSettings(
        issuer_url=verifier.issuer,  # pyright: ignore[reportArgumentType]
        resource_server_url=verifier.resource,  # pyright: ignore[reportArgumentType]
        required_scopes=advertised_scopes(scopes),
        validate_token_resource=True,
    )


class GotAuthTokenVerifier:
    """The SDK's ``TokenVerifier``, plus :meth:`guard` for spec-correct challenges.

    The SDK's own 401 and 403 headers are wrong (python-sdk #3103), so wrap its app::

        settings, verifier = mcp_sdk_auth(auth, resource=URL, scopes=["projects:read"])
        server = MCPServer("projects", auth=settings, token_verifier=verifier)
        app = verifier.guard(server.streamable_http_app(stateless_http=True),
                             tool_scopes={"create_project": ["projects:write"]})
    """

    def __init__(self, verifier: Verifier, scopes: Sequence[str]) -> None:
        self.gotauth = verifier
        self.scopes = list(scopes)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a GotAuth access token for the SDK's bearer backend."""
        verified = verified_in_request(token) or await self.gotauth.verify(token)
        if verified is None:
            return None
        access = verified.access
        return AccessToken(
            token=token,
            client_id=access.client_id,
            scopes=sorted(access.scopes),
            expires_at=access.expires_at,
            resource=self.gotauth.resource,
            subject=access.user_id,
            claims={**verified.claims, CLAIMS_KEY: access.to_claims()},
        )

    def guard(
        self,
        app: Any,  # Any: the SDK's Starlette app
        *,
        tool_scopes: Mapping[str, Sequence[str]] | None = None,
        path: str | None = None,
    ) -> App:
        """Wrap the SDK's app: GotAuth answers 401 and 403 and serves the RFC 9728
        document.

        Args:
            app: ``server.streamable_http_app(...)``.
            tool_scopes: Scopes each tool needs beyond the configured ones; a call
                without them is a 403 ``insufficient_scope`` before the tool runs.
            path: The MCP endpoint's path inside ``app``; defaults to the resource
                URL's path.
        """
        needs = {name: list(scopes) for name, scopes in (tool_scopes or {}).items()}

        async def scopes_for(_: Scope, name: str, __: Verified) -> list[str]:
            return needs.get(name, [])

        return McpGuard(
            app,
            verifier=self.gotauth,
            scopes=self.scopes,
            path=path,
            tool_scopes=scopes_for if needs else None,
        )
