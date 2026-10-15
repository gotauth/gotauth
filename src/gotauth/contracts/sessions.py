"""CONTRACTS section 7: sessions, token formats and cookie names."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, field_validator

from gotauth.contracts.primitives import Duration, to_timedelta

if TYPE_CHECKING:
    from gotauth.contracts.core_schema import Session, User
    from gotauth.contracts.endpoints import EndpointContext

__all__ = [
    "COOKIE_NAMES",
    "JWT_PREFIX",
    "TOKEN_PREFIXES",
    "CookieCacheConfig",
    "CreatedSession",
    "SecondaryStorage",
    "SessionConfig",
    "SessionService",
    "SessionWithUser",
    "cookie_name",
    "is_localhost",
    "secure_cookies",
]

TOKEN_PREFIXES: Mapping[str, str] = MappingProxyType(
    {
        "session_token": "gas_",
        "api_key": "gak_",
        "oauth_refresh_token": "gar_",
        "oauth_authorization_code": "gac_",
        "verification_token": "gav_",
        "oauth_client_secret": "gcs_",
    }
)
"""Token kind -> prefix (section 7). Bodies are 32 random bytes, base64url."""

JWT_PREFIX = "eyJ"
"""OAuth access tokens are JWTs, so they start with this (section 12.2)."""

COOKIE_NAMES: Mapping[str, str] = MappingProxyType(
    {
        "session_token": "C3",
        "session_data": "C3",
        "challenge": "C1",
        "oauth_state": "C4",
        "two_factor_trust": "P2",
        "passkey_challenge": "P3",
        "admin_session": "P6",
    }
)
"""Cookie base name -> owning work package. A new cookie needs a CCR."""

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})


def is_localhost(url: str) -> bool:
    """Return True if the URL's host is ``localhost`` or ``127.0.0.1`` (any scheme)."""
    return (urlsplit(url).hostname or "").lower() in _LOCAL_HOSTS


def secure_cookies(base_url: str) -> bool:
    """Return whether cookies get the ``Secure`` flag.

    False only for ``http://localhost`` and ``http://127.0.0.1`` (any port), so local
    development works without TLS. Every other URL, ``http`` included, gets ``Secure``.
    """
    return not (urlsplit(base_url).scheme.lower() == "http" and is_localhost(base_url))


def cookie_name(base: str, *, base_url: str, prefix: str) -> str:
    """Return the full name of a GotAuth cookie.

    Args:
        base: A base name from :data:`COOKIE_NAMES`, e.g. ``"session_token"``.
        base_url: The configured external origin.
        prefix: ``advanced.cookie_prefix`` (default ``"gotauth"``).

    Returns:
        ``"<prefix>.<base>"``, with ``"__Secure-"`` in front when ``base_url`` is https,
        e.g. ``"__Secure-gotauth.session_token"``.
    """
    name = f"{prefix}.{base}"
    if urlsplit(base_url).scheme.lower() == "https":
        return "__Secure-" + name
    return name


def _check_duration(value: Duration) -> Duration:
    to_timedelta(value)
    return value


class CookieCacheConfig(BaseModel):
    """The optional signed ``session_data`` cookie cache."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    max_age: Duration = "5m"

    @field_validator("max_age")
    @classmethod
    def _valid_duration(cls, value: Duration) -> Duration:
        return _check_duration(value)


class SessionConfig(BaseModel):
    """Session settings (section 7). Durations are validated with ``to_timedelta``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expires_in: Duration = "7d"
    update_age: Duration = "1d"
    """Sliding refresh: once a session is older than this since its last update,
    ``expires_at`` moves forward."""
    fresh_age: Duration = "1d"
    short_expires_in: Duration = "1d"
    """Server expiry for ``remember_me=False``."""
    absolute_lifetime: Duration | None = "30d"
    """No session outlives ``created_at`` plus this, however often it slides;
    ``None`` turns the cap off."""
    allow_bearer: bool = True
    expose_token: bool = False
    """When True, sign-in responses include ``token`` for native and CLI clients."""
    cookie_cache: CookieCacheConfig = CookieCacheConfig()

    @field_validator("expires_in", "update_age", "fresh_age", "short_expires_in")
    @classmethod
    def _valid_duration(cls, value: Duration) -> Duration:
        return _check_duration(value)

    @field_validator("absolute_lifetime")
    @classmethod
    def _valid_optional_duration(cls, value: Duration | None) -> Duration | None:
        return None if value is None else _check_duration(value)


@dataclass(frozen=True)
class CreatedSession:
    """A new session and its raw token. The token is returned once and left out of
    ``repr()``."""

    session: Session
    token: str = dc_field(repr=False)


@dataclass(frozen=True)
class SessionWithUser:
    """A session with its user."""

    session: Session
    user: User


@runtime_checkable
class SessionService(Protocol):
    """Creates, reads and revokes sessions (C3)."""

    async def create(
        self,
        ctx: EndpointContext,
        user_id: str,
        *,
        remember_me: bool = True,
        expires_in: Duration | None = None,
        extra: Mapping[str, Any] | None = None,  # Any: plugin fields of the session row
    ) -> CreatedSession:
        """Create a session with a new token and set the session cookie."""
        ...

    async def get(self, ctx: EndpointContext, token: str) -> SessionWithUser | None:
        """Return the session for a raw token; checks expiry and slides it."""
        ...

    async def list_for_user(self, ctx: EndpointContext, user_id: str) -> list[Session]:
        """Return a user's sessions."""
        ...

    async def revoke(self, ctx: EndpointContext, session_id: str) -> bool:
        """Delete one session; return whether it existed."""
        ...

    async def revoke_all(
        self,
        ctx: EndpointContext,
        user_id: str,
        *,
        except_session_id: str | None = None,
    ) -> int:
        """Delete a user's sessions, optionally keeping one; return how many."""
        ...

    def clear_cookies(self, ctx: EndpointContext) -> None:
        """Delete the session and cookie-cache cookies."""
        ...


@runtime_checkable
class SecondaryStorage(Protocol):
    """Optional key-value storage, e.g. Redis."""

    async def get(self, key: str) -> str | None:
        """Return the value, or ``None``."""
        ...

    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        """Store a value, optionally with a TTL."""
        ...

    async def delete(self, key: str) -> None:
        """Delete a key."""
        ...

    async def incr(self, key: str, ttl_seconds: int) -> int:
        """Increment atomically; the TTL is set on the first increment."""
        ...
