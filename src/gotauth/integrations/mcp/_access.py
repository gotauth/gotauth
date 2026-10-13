"""``GotAuthAccess``: who an MCP request acts for (CONTRACTS 12.1 and 12.4)."""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from typing import Any

__all__ = ["GotAuthAccess", "current_access"]

CLAIMS_KEY = "gotauth"
"""Key of the access fields inside the framework token's ``claims``."""


@dataclass(frozen=True)
class GotAuthAccess:
    """A verified GotAuth access token.

    Attributes:
        user_id: The human the token acts for. Never an agent or client id: a
            ``client_credentials`` token has none.
        agent_id: The agent acting (the ``act.sub`` claim), if any.
        client_id: The OAuth client the token was issued to.
        scopes: Granted scopes.
        jti: The token id; ``revoke_oauth_tokens`` and ``revoke_oauth_grant`` act on it.
        expires_at: Expiry as a Unix timestamp.
    """

    user_id: str | None
    agent_id: str | None
    client_id: str
    scopes: frozenset[str]
    jti: str
    expires_at: int | None = None

    def to_claims(self) -> dict[str, Any]:  # Any: JSON
        """The fields as JSON values, for a framework token's ``claims``."""
        data = asdict(self)
        data["scopes"] = sorted(self.scopes)
        return data

    @classmethod
    def from_claims(cls, data: Mapping[str, Any]) -> GotAuthAccess:  # Any: JSON
        """The inverse of :meth:`to_claims`."""
        return cls(
            user_id=data.get("user_id"),
            agent_id=data.get("agent_id"),
            client_id=str(data["client_id"]),
            scopes=frozenset(data.get("scopes") or ()),
            jti=str(data["jti"]),
            expires_at=data.get("expires_at"),
        )


current: ContextVar[GotAuthAccess | None] = ContextVar(
    "gotauth_mcp_access", default=None
)


def current_access() -> GotAuthAccess | None:
    """The access of the MCP request being handled, or ``None`` outside one.

    Works in FastMCP tools and MCP SDK handlers: it reads GotAuth's own context first,
    then the framework's access token (the frameworks may run a tool in another task).
    """
    found = current.get()
    if found is not None:
        return found
    for token in _framework_tokens():
        claims = getattr(token, "claims", None)
        if isinstance(claims, Mapping) and CLAIMS_KEY in claims:
            return GotAuthAccess.from_claims(claims[CLAIMS_KEY])  # pyright: ignore[reportUnknownArgumentType]
    return None


def _framework_tokens() -> list[Any]:  # Any: AccessToken of FastMCP or the MCP SDK
    tokens: list[Any] = []
    try:
        from fastmcp.server.dependencies import get_access_token as fastmcp_token

        tokens.append(fastmcp_token())
    except Exception:  # noqa: S110 - FastMCP missing or outside a request
        pass
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token

        tokens.append(get_access_token())
    except Exception:  # noqa: S110 - the SDK missing or outside a request
        pass
    return [token for token in tokens if token is not None]
