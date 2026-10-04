"""CONTRACTS section 4: the framework-neutral request and response types."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import TYPE_CHECKING, Any, Literal, TypeAlias

if TYPE_CHECKING:
    from pydantic import BaseModel

__all__ = [
    "ASGIApp",
    "ASGIReceive",
    "ASGIScope",
    "ASGISend",
    "AuthRequest",
    "AuthResponse",
    "SetCookie",
]

# Any: ASGI messages and scopes are dicts of arbitrary values (ASGI specification).
ASGIScope: TypeAlias = MutableMapping[str, Any]
ASGIReceive: TypeAlias = Callable[[], Awaitable[MutableMapping[str, Any]]]
ASGISend: TypeAlias = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp: TypeAlias = Callable[[ASGIScope, ASGIReceive, ASGISend], Awaitable[None]]
"""An ASGI 3 application, returned by ``auth.asgi()`` and ``auth.well_known()``."""


@dataclass(frozen=True)
class AuthRequest:
    """A request, as an integration hands it to the core.

    Headers, cookies, query, URL and body are left out of ``repr()`` because they can
    carry credentials.

    Attributes:
        method: Upper-case HTTP method.
        path: Path relative to the mount, e.g. ``"/sign-in/email"``.
        url: Full external URL, for redirects and origin checks.
        query: Query parameters.
        headers: Headers with lower-case keys.
        cookies: Cookies by name.
        body: The raw body.
        client_ip: Resolved with ``resolve_client_ip()``.
    """

    method: str
    path: str
    url: str = dc_field(repr=False)
    query: Mapping[str, str] = dc_field(repr=False)
    headers: Mapping[str, str] = dc_field(repr=False)
    cookies: Mapping[str, str] = dc_field(repr=False)
    body: bytes = dc_field(repr=False)
    client_ip: str | None


@dataclass(frozen=True)
class SetCookie:
    """A ``Set-Cookie`` instruction; ``value=""`` with ``max_age=0`` deletes it."""

    name: str
    value: str = dc_field(repr=False)
    max_age: int | None = None
    path: str = "/"
    domain: str | None = None
    secure: bool = True
    http_only: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"


@dataclass
class AuthResponse:
    """A response from the core. Every JSON response has ``Cache-Control: no-store``.

    Attributes:
        status: HTTP status.
        body: Serialized as JSON.
        html: A server-rendered page (consent, error).
        redirect: Sets 302 and ``Location``.
        headers: Extra headers.
        cookies: Cookies to set or delete.
    """

    status: int = 200
    # Any: JSON bodies may be any mapping of JSON values.
    body: BaseModel | Mapping[str, Any] | None = dc_field(default=None, repr=False)
    html: str | None = dc_field(default=None, repr=False)
    redirect: str | None = dc_field(default=None, repr=False)
    headers: dict[str, str] = dc_field(default_factory=dict[str, str])
    cookies: list[SetCookie] = dc_field(default_factory=list[SetCookie], repr=False)
