"""URL rules of the OAuth server (CONTRACTS 12.3): redirect URIs and resources."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from gotauth.contracts.errors import ConfigError
from gotauth.contracts.primitives import Duration, to_timedelta

__all__ = [
    "LOOPBACK_HOSTS",
    "Settings",
    "is_loopback_redirect",
    "normalize_resource",
    "redirect_matches",
    "valid_redirect_uri",
]

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_DOT_SEGMENT = re.compile(r"(^|/)\.{1,2}(/|$)")
SUPPORTED_ALGS = ("ES256", "RS256")


def valid_redirect_uri(uri: str) -> bool:
    """``https``, or ``http`` on a loopback host; no fragment, no userinfo."""
    try:
        parts = urlsplit(uri)
        hostname = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError:
        return False
    if not hostname or parts.fragment or "#" in uri or parts.username or parts.password:
        return False
    if any(ch.isspace() for ch in uri):
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and hostname in LOOPBACK_HOSTS


def is_loopback_redirect(uri: str) -> bool:
    """``http`` on ``localhost``, ``127.0.0.1`` or ``[::1]``."""
    try:
        parts = urlsplit(uri)
        return parts.scheme == "http" and (parts.hostname or "") in LOOPBACK_HOSTS
    except ValueError:
        return False


def redirect_matches(registered: str, presented: str) -> bool:
    """Exact string match, except that a loopback host's port may differ (RFC 8252
    section 7.3)."""
    if registered == presented:
        return True
    if not (is_loopback_redirect(registered) and is_loopback_redirect(presented)):
        return False
    a, b = urlsplit(registered), urlsplit(presented)
    return (a.scheme, a.hostname, a.path, a.query) == (
        b.scheme,
        b.hostname,
        b.path,
        b.query,
    )


def normalize_resource(uri: str) -> str | None:
    """Normalize a resource indicator (RFC 8707): lowercase the scheme and host, drop a
    default port, keep the path exactly. ``None`` for fragments, dot segments, relative
    or non-http(s) URIs."""
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host or parts.fragment or "#" in uri:
        return None
    if parts.username or parts.password or _DOT_SEGMENT.search(parts.path):
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = (
        host if port is None or port == _DEFAULT_PORTS[scheme] else f"{host}:{port}"
    )
    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


@dataclass(frozen=True)
class Settings:
    """The ``oauth_provider(...)`` options, checked and normalized."""

    login_page: str = "/sign-in"
    consent_page: str | None = None
    scopes: tuple[str, ...] = ("openid", "profile", "email", "offline_access")
    resources: tuple[str, ...] = ()
    access_token_ttl: Duration = "10m"  # noqa: S105 - a duration, not a password
    refresh_token_ttl: Duration = "30d"  # noqa: S105
    signing_alg: str = "ES256"
    allow_cimd: bool = True
    allow_dynamic_registration: bool = False
    mcp: bool = False
    normalized_resources: tuple[str, ...] = field(default=(), init=False)

    def __post_init__(self) -> None:
        if self.signing_alg not in SUPPORTED_ALGS:
            msg = f"signing_alg must be one of {SUPPORTED_ALGS}"
            raise ConfigError(msg)
        normalized: list[str] = []
        for resource in self.resources:
            value = normalize_resource(resource)
            if value is None:
                msg = (
                    f"invalid resource {resource!r}: absolute http(s) URI, no fragment"
                )
                raise ConfigError(msg)
            normalized.append(value)
        object.__setattr__(self, "normalized_resources", tuple(normalized))
        to_timedelta(self.access_token_ttl)
        to_timedelta(self.refresh_token_ttl)
        if self.mcp and not self.allow_cimd:
            raise ConfigError("oauth_provider(mcp=True) needs allow_cimd=True")

    def resource(self, requested: Sequence[str]) -> str | bool | None:
        """The normalized resource for a request: ``None`` when absent, ``False`` when
        invalid or not allowed."""
        if not requested:
            return None
        if len(requested) > 1:
            return False
        value = normalize_resource(requested[0])
        if value is None or value not in self.normalized_resources:
            return False
        return value
