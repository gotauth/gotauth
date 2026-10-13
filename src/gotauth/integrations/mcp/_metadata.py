"""RFC 9728 protected resource metadata and the ``WWW-Authenticate`` challenges
(CONTRACTS 12.4, MCP authorization 2026-07-28)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from gotauth.contracts.errors import ConfigError

__all__ = [
    "advertised_scopes",
    "insufficient_scope",
    "invalid_token",
    "metadata_path",
    "metadata_url",
    "missing_token",
    "normalize_resource",
    "protected_resource_metadata",
]

OFFLINE_ACCESS = "offline_access"
_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_resource(resource: str) -> str:
    """The resource URL as GotAuth's authorization server writes it into ``aud``:
    lowercase scheme and host, no default port, the path kept exactly.

    Raises:
        ConfigError: For a relative, non-http(s) or fragment URL.
    """
    try:
        parts = urlsplit(resource)
        port = parts.port
    except ValueError:
        port = -1
        parts = urlsplit("")
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if port == -1 or scheme not in _DEFAULT_PORTS or not host or "#" in resource:
        msg = "resource must be an absolute http(s) URL without a fragment"
        raise ConfigError(msg)
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


def advertised_scopes(scopes: Sequence[str]) -> list[str]:
    """``scopes`` without duplicates and without ``offline_access``, which a protected
    resource never advertises or requires (MCP 2026-07-28, Refresh Tokens)."""
    return [scope for scope in dict.fromkeys(scopes) if scope != OFFLINE_ACCESS]


def protected_resource_metadata(
    *, resource: str, issuer: str, scopes: Sequence[str]
) -> dict[str, Any]:  # Any: JSON
    """The RFC 9728 document for an MCP server protected by GotAuth.

    Args:
        resource: The MCP server's URL, for example ``"https://api.example.com/mcp"``.
        issuer: GotAuth's issuer (``base_url + base_path``).
        scopes: The scopes the server uses; ``offline_access`` is left out.

    Returns:
        The document: ``resource``, ``authorization_servers``, ``scopes_supported``
        and ``bearer_methods_supported``.
    """
    return {
        "resource": resource,
        "authorization_servers": [issuer],
        "scopes_supported": advertised_scopes(scopes),
        "bearer_methods_supported": ["header"],
    }


def metadata_path(resource: str) -> str:
    """Where the metadata lives on the resource's host (RFC 9728 section 3.1: the
    well-known prefix goes before the resource's path)."""
    path = urlsplit(resource).path.rstrip("/")
    return "/.well-known/oauth-protected-resource" + path


def metadata_url(resource: str) -> str:
    """The absolute URL of :func:`metadata_path`."""
    parts = urlsplit(resource)
    return f"{parts.scheme}://{parts.netloc}{metadata_path(resource)}"


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def missing_token(url: str, scopes: Sequence[str]) -> str:
    """401 without a token: ``Bearer resource_metadata="...", scope="..."``."""
    parts = [f"resource_metadata={_quote(url)}"]
    if scopes:
        parts.append(f"scope={_quote(' '.join(scopes))}")
    return "Bearer " + ", ".join(parts)


def invalid_token(url: str, scopes: Sequence[str]) -> str:
    """401 for a bad or expired token: ``error="invalid_token"`` comes first."""
    return 'Bearer error="invalid_token", ' + missing_token(url, scopes)[7:]


def insufficient_scope(url: str, needed: Sequence[str]) -> str:
    """403: ``Bearer error="insufficient_scope", scope="...", resource_metadata="..."``,
    with every scope the call needs."""
    return (
        'Bearer error="insufficient_scope", '
        f"scope={_quote(' '.join(needed))}, resource_metadata={_quote(url)}"
    )
