"""CONTRACTS section 10 and the shared helpers of section 4.

``resolve_client_ip`` and ``validate_redirect`` live here so integrations and plugins
can use them before the core (C1) exists. ``gotauth.core`` re-exports them. Every
module must use these helpers, never its own copies.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypeAlias
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, field_validator
from pydantic import Field as PydanticField

from gotauth.contracts.endpoints import EndpointContext
from gotauth.contracts.errors import AuthError
from gotauth.contracts.primitives import Duration, to_timedelta

if TYPE_CHECKING:
    from gotauth.contracts.config import ResolvedConfig

__all__ = [
    "DEFAULT_RATE_LIMITS",
    "IdentifierFn",
    "RateLimitConfig",
    "RateLimitKey",
    "RateLimitRule",
    "is_trusted_origin",
    "normalize_origin",
    "resolve_client_ip",
    "validate_redirect",
]

RateLimitKey: TypeAlias = Literal["ip", "ip_path", "principal", "identifier"]

# Any: the identifier function receives the validated input model of the endpoint.
IdentifierFn: TypeAlias = Callable[[EndpointContext, Any], str | None]


@dataclass(frozen=True)
class RateLimitRule:
    """A fixed-window rate limit.

    Attributes:
        path: Exact path, or a prefix ending in ``*`` (``"/sign-in/*"``); ``"*"``
            matches every path.
        window: Window length.
        max: Requests allowed per window.
        key: What is counted: per IP, per IP + path, per principal or per identifier.
        identifier: For ``key="identifier"``: an input field name (e.g. ``"email"``,
            lower-cased) or a function of ``(ctx, input)``. The value is hashed before
            it is stored; ``None`` from the function skips the rule.
    """

    path: str
    window: Duration
    max: int
    key: RateLimitKey = "ip_path"
    identifier: str | IdentifierFn | None = None


class RateLimitConfig(BaseModel):
    """Rate-limit settings (10.2). Rules are added to and override the defaults."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    storage: Literal["memory", "database", "secondary"] = "memory"
    """``"database"`` uses the C1-owned ``rate_limit`` model."""
    rules: list[RateLimitRule] = PydanticField(default_factory=list[RateLimitRule])

    @field_validator("rules")
    @classmethod
    def _valid_rules(cls, rules: list[RateLimitRule]) -> list[RateLimitRule]:
        for rule in rules:
            to_timedelta(rule.window)
        return rules


_AUTH_FLOWS = (
    "/sign-in/*",
    "/sign-up/*",
    "/request-password-reset",
    "/reset-password",
    "/send-verification-email",
    "/two-factor/*",
    "/magic-link/*",
    "/email-otp/*",
)
_EMAIL_IDENTIFIED = (
    "/sign-in/email",
    "/request-password-reset",
    "/magic-link/send",
    "/email-otp/send",
)

DEFAULT_RATE_LIMITS: tuple[RateLimitRule, ...] = (
    RateLimitRule(path="*", window="60s", max=100, key="ip_path"),
    *(
        RateLimitRule(path=path, window="60s", max=5, key="ip_path")
        for path in _AUTH_FLOWS
    ),
    # Per email address: blocks distributed credential stuffing and email bombing.
    *(
        RateLimitRule(
            path=path, window="15m", max=10, key="identifier", identifier="email"
        )
        for path in _EMAIL_IDENTIFIED
    ),
    RateLimitRule(path="/passkey/*", window="60s", max=10, key="ip_path"),
    RateLimitRule(path="/oauth2/token", window="60s", max=30, key="ip_path"),
)
"""The section 10.2 defaults."""

_Address: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
_Network: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_ip(value: str) -> _Address | None:
    text = value.strip()
    if text.startswith("["):
        # "[::1]" or "[::1]:8080"
        end = text.find("]")
        if end == -1:
            return None
        text = text[1:end]
    elif text.count(":") == 1:
        # "203.0.113.7:51234"; a bare IPv6 address has more than one colon.
        text = text.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _networks(entries: Sequence[str]) -> list[_Network]:
    networks: list[_Network] = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            continue
    return networks


def _trusted(address: _Address, networks: Sequence[_Network]) -> bool:
    return any(address.version == net.version and address in net for net in networks)


def resolve_client_ip(
    peer: str | None, headers: Mapping[str, str], config: ResolvedConfig
) -> str | None:
    """Return the client IP of a request.

    ``advanced.ip_headers`` (e.g. ``("x-forwarded-for",)``) are honored only when the
    direct peer is in ``advanced.trusted_proxies`` (addresses or CIDR networks). The
    header is then read from right to left, skipping trusted proxies, and the
    right-most entry that is not a trusted proxy wins. Anything a client prepends to
    the header is therefore ignored.

    Args:
        peer: The address of the direct TCP peer, as the server reports it.
        headers: Request headers with lower-case keys.
        config: The resolved configuration.

    Returns:
        The client address in canonical form, or the peer as given when it cannot be
        parsed, or ``None`` when there is no peer.
    """
    if peer is None:
        return None
    peer_ip = _parse_ip(peer)
    if peer_ip is None:
        return peer
    advanced = config.advanced
    proxies = _networks(advanced.trusted_proxies)
    if not advanced.ip_headers or not _trusted(peer_ip, proxies):
        return str(peer_ip)
    for header in advanced.ip_headers:
        value = headers.get(header.lower())
        if not value:
            continue
        entries = [entry for entry in value.split(",") if entry.strip()]
        leftmost: _Address | None = None
        for entry in reversed(entries):
            address = _parse_ip(entry)
            if address is None:
                # A malformed hop: stop trusting the header and fall back to the peer.
                return str(peer_ip)
            if not _trusted(address, proxies):
                return str(address)
            leftmost = address
        if leftmost is not None:
            # Every hop is a trusted proxy: the request started inside the network.
            return str(leftmost)
    return str(peer_ip)


_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_origin(url: str) -> str | None:
    """Return ``scheme://host[:port]`` in lower case without a default port.

    Returns ``None`` when the URL has no origin here.

    Only http and https URLs with a host and no userinfo have one.
    """
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host or "@" in parts.netloc:
        return None
    if ":" in host:
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _origin_matches(origin: str, pattern: str) -> bool:
    if "://*." in pattern:
        scheme, rest = pattern.split("://*.", 1)
        wildcard = normalize_origin(f"{scheme}://wildcard.{rest}")
        if wildcard is None:
            return False
        # "https://*.example.com" matches any subdomain, never the bare domain.
        prefix, suffix = wildcard.split("://wildcard.", 1)
        head = f"{prefix}://"
        if not origin.startswith(head):
            return False
        host_and_port = origin[len(head) :]
        return (
            host_and_port.endswith("." + suffix)
            and len(host_and_port) > len(suffix) + 1
        )
    normalized = normalize_origin(pattern)
    return normalized is not None and normalized == origin


def is_trusted_origin(origin: str, config: ResolvedConfig) -> bool:
    """Return True for the origin of ``base_url`` or one matching a trusted origin.

    Trusted origins are exact origins or ``https://*.example.com`` wildcards (any
    subdomain, not the bare domain).
    """
    normalized = normalize_origin(origin)
    if normalized is None:
        return False
    if normalized == normalize_origin(config.base_url):
        return True
    return any(
        _origin_matches(normalized, pattern) for pattern in config.trusted_origins
    )


def validate_redirect(url: str, config: ResolvedConfig) -> str:
    """Check a redirect parameter.

    Applies to ``callback_url``, ``error_callback_url`` and ``redirect_to``. Allowed:
    a path starting with a single ``/`` (not ``//x`` or ``/\\x``), or an absolute
    http(s) URL whose origin is ``base_url`` or a trusted origin. URLs with userinfo,
    backslashes, whitespace or control characters are rejected.

    Args:
        url: The submitted value.
        config: The resolved configuration.

    Returns:
        The URL unchanged.

    Raises:
        AuthError: ``INVALID_REQUEST`` when the URL is not allowed.
    """
    if _safe_redirect(url, config):
        return url
    raise AuthError("INVALID_REQUEST", 400, "Redirect URL is not allowed")


def _safe_redirect(url: str, config: ResolvedConfig) -> bool:
    if (
        not url
        or "\\" in url
        or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in url)
    ):
        # Browsers strip tabs and newlines and treat "\" like "/", which turns
        # "/\t/evil.com" or "/\\evil.com" into a protocol-relative URL.
        return False
    if url.startswith("/"):
        return not url.startswith("//")
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme.lower() not in _DEFAULT_PORTS or parts.username is not None:
        return False
    origin = normalize_origin(url)
    return origin is not None and is_trusted_origin(origin, config)
