"""The FastMCP auth provider (needs ``pip install "gotauth[mcp]"``)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast
from urllib.parse import urlsplit

from fastmcp.server.auth import AccessToken, RemoteAuthProvider, TokenVerifier
from fastmcp.utilities.authorization import AuthContext, run_auth_checks_with_shortfall
from pydantic import AnyHttpUrl
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from gotauth.integrations.mcp._access import CLAIMS_KEY
from gotauth.integrations.mcp._guard import McpGuard, Scope, verified_in_request
from gotauth.integrations.mcp._metadata import (
    advertised_scopes,
    metadata_path,
    protected_resource_metadata,
)
from gotauth.integrations.mcp._verify import Verified, Verifier

__all__ = ["GotAuthProvider", "access_token"]


def access_token(token: str, verified: Verified) -> AccessToken:
    """The framework token for a verified GotAuth token; its ``claims`` hold the JWT
    claims and, under ``"gotauth"``, the :class:`GotAuthAccess` fields."""
    access = verified.access
    return AccessToken(
        token=token,
        client_id=access.client_id,
        scopes=sorted(access.scopes),
        expires_at=access.expires_at,
        resource=_resource(verified) or None,
        subject=access.user_id,
        claims={**verified.claims, CLAIMS_KEY: access.to_claims()},
    )


def _resource(verified: Verified) -> str:
    aud = verified.claims.get("aud")
    return aud if isinstance(aud, str) else str(next(iter(aud or []), ""))


class _Verifier(TokenVerifier):
    def __init__(self, verifier: Verifier, scopes: Sequence[str]) -> None:
        super().__init__(required_scopes=advertised_scopes(scopes))
        self.gotauth = verifier

    async def verify_token(self, token: str) -> AccessToken | None:
        verified = verified_in_request(token) or await self.gotauth.verify(token)
        return None if verified is None else access_token(token, verified)


async def _tool_scopes(scope: Scope, name: str, verified: Verified) -> list[str]:
    """Every scope a FastMCP tool's ``require_scopes`` checks ask for, whether the
    token has them or not (none for an unknown tool), so a 403 names all the scopes
    the call needs. Other checks, such as roles, are left to FastMCP."""
    app = scope.get("app")
    server = getattr(getattr(app, "state", None), "fastmcp_server", None)
    if server is None:
        return []
    tool = await _unfiltered_tool(server, name)
    if tool is None or not getattr(tool, "auth", None):
        return []
    # Checked against a token with no scopes, the shortfall is every scope that
    # applies to this tool (a tag-restricted check without its tag asks for none).
    empty = access_token("", verified).model_copy(update={"scopes": []})
    _, needed = await run_auth_checks_with_shortfall(
        tool.auth, AuthContext(token=empty, component=tool)
    )
    return sorted(needed)


async def _unfiltered_tool(server: Any, name: str) -> Any:  # Any: FastMCP, Tool
    """The tool named ``name``, even when the token may not see it.

    ``get_tool`` hides a tool whose auth checks the current token fails, which is
    exactly the tool the guard must answer with a 403. FastMCP 4.0 skips component
    auth for stdio, so the lookup runs in that mode. Without that hook the guard finds
    nothing and FastMCP answers the call itself.
    """
    try:
        from fastmcp.server.context import (
            _current_transport,  # pyright: ignore[reportPrivateUsage]
        )
    except ImportError:  # pragma: no cover - a FastMCP without the hook
        return None
    marker = _current_transport.set("stdio")
    try:
        return await server.get_tool(name)
    except Exception:  # an unknown tool: FastMCP answers the call
        return None
    finally:
        _current_transport.reset(marker)


class GotAuthProvider(RemoteAuthProvider):
    """FastMCP's remote-provider pattern with GotAuth's verifier and guard.

    The guard answers every 401 and 403 with the CONTRACTS 12.4 challenges and checks
    a called tool's ``require_scopes`` before FastMCP runs it, so a missing tool scope
    is an HTTP 403 a client can step up from, not a JSON-RPC error.
    """

    def __init__(self, verifier: Verifier, scopes: Sequence[str]) -> None:
        parts = urlsplit(verifier.resource)
        super().__init__(
            token_verifier=_Verifier(verifier, scopes),
            authorization_servers=[AnyHttpUrl(verifier.issuer)],
            base_url=f"{parts.scheme}://{parts.netloc}",
            scopes_supported=advertised_scopes(scopes),
        )
        self.gotauth = verifier
        self.gotauth_scopes = list(scopes)

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """The RFC 9728 document at its path form on the resource's host."""
        self.set_mcp_path(mcp_path)
        document = protected_resource_metadata(
            resource=self.gotauth.resource,
            issuer=self.gotauth.issuer,
            scopes=self.gotauth_scopes,
        )

        async def metadata(_: Request) -> JSONResponse:
            return JSONResponse(document, headers={"access-control-allow-origin": "*"})

        return [
            Route(
                metadata_path(self.gotauth.resource),
                endpoint=metadata,
                methods=["GET", "HEAD"],
            )
        ]

    def get_middleware(self) -> list[Any]:  # Any: Starlette Middleware
        """GotAuth's guard first, then FastMCP's own (which sets the access token)."""
        provider = self

        def guard(app: Any) -> McpGuard:  # Any: an ASGI app
            return McpGuard(
                app,
                verifier=provider.gotauth,
                scopes=provider.gotauth_scopes,
                path=lambda: provider._mcp_path,  # pyright: ignore[reportPrivateUsage]
                tool_scopes=_tool_scopes,
            )

        # FastMCP's own list is unannotated; it holds Starlette Middleware.
        own = cast(
            list[Any],
            super().get_middleware(),  # pyright: ignore[reportUnknownMemberType]
        )
        return [Middleware(guard), *own]
