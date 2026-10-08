"""OAuth clients: static and dynamic ones in the database, and CIMD documents."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import re
import socket
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import unquote, urlsplit

import httpx

from gotauth.contracts.adapter import Where
from gotauth.contracts.endpoints import EndpointContext
from gotauth.contracts.errors import AuthError

from ._rules import Settings, valid_redirect_uri

__all__ = [
    "CimdError",
    "ClientStore",
    "Resolver",
    "authenticate_client",
    "is_cimd_url",
    "oauth_error",
]

Resolver = Callable[[str, int], Awaitable[list[str]]]
"""``(host, port) -> IP addresses``; replaceable in tests."""

_MAX_DOCUMENT = 5 * 1024
_TIMEOUT = 5.0
_MIN_TTL, _MAX_TTL, _DEFAULT_TTL = 60.0, 24 * 3600.0, 300.0
_DOT_SEGMENT = re.compile(r"(^|/)\.{1,2}(/|$)")
_MAX_AGE = re.compile(r"max-age=(\d+)")


def oauth_error(
    error: str, status: int = 400, description: str | None = None
) -> AuthError:
    """An RFC 6749 error; C1 renders ``OAUTH_<NAME>`` as ``error=<name>``."""
    headers = (
        {"www-authenticate": 'Basic realm="oauth"'}
        if error == "invalid_client"
        else None
    )
    return AuthError(
        f"OAUTH_{error.upper()}", status, description or error, headers=headers
    )


class CimdError(Exception):
    """A client ID metadata document was refused; the message is safe to show."""


def is_cimd_url(client_id: str) -> bool:
    """An https URL with a non-empty path, no fragment, no userinfo, no dot segments."""
    try:
        parts = urlsplit(client_id)
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and bool(parts.hostname)
        and parts.path not in ("", "/")
        and not parts.fragment
        and "#" not in client_id
        and not parts.username
        and not parts.password
        and not _DOT_SEGMENT.search(unquote(parts.path))
    )


async def _system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    )
    return sorted({str(info[4][0]) for info in infos})


def _public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and (
        ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None
    ):
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local)
    )


@dataclass
class _Cached:
    document: dict[str, Any]  # Any: JSON
    expires: float


class ClientStore:
    """Looks up clients; CIMD documents are fetched, checked, cached and stored."""

    def __init__(self, settings: Settings, resolver: Resolver | None = None) -> None:
        self._settings = settings
        self.resolver: Resolver = resolver or _system_resolver
        self._cache: dict[str, _Cached] = {}
        self.now: Callable[[], float] = time.monotonic

    async def get(
        self, ctx: EndpointContext, client_id: str
    ) -> dict[str, Any] | None:  # Any: row
        """The client row, loading a CIMD document when ``client_id`` is its URL."""
        row = await ctx.adapter.find_one(
            "oauth_client", [Where("client_id", client_id)]
        )
        if self._settings.allow_cimd and is_cimd_url(client_id):
            if row is not None and row["registration"] != "cimd":
                return row
            document = await self.fetch(ctx, client_id)
            return await self._store(ctx, client_id, document, row)
        return row

    async def _store(
        self,
        ctx: EndpointContext,
        client_id: str,
        document: Mapping[str, Any],  # Any: JSON
        row: dict[str, Any] | None,  # Any: row
    ) -> dict[str, Any]:  # Any: row
        values = {
            "name": str(document["client_name"]),
            "redirect_uris": list(document["redirect_uris"]),
            "grant_types": list(
                document.get("grant_types") or ["authorization_code", "refresh_token"]
            ),
        }
        if row is not None:
            if row.get("disabled_at") is not None:
                return row
            updated = await ctx.adapter.update(
                "oauth_client", [Where("id", row["id"])], values
            )
            return updated or row
        return await ctx.adapter.create(
            "oauth_client",
            {
                "id": ctx.ids.new("cli"),
                "client_id": client_id,
                "type": "public",
                "scopes": list(self._settings.scopes),
                "registration": "cimd",
                "created_at": ctx.clock.now(),
                **values,
            },
        )

    async def fetch(
        self, ctx: EndpointContext, url: str
    ) -> dict[str, Any]:  # Any: JSON
        """Fetch and check a CIMD document.

        Raises:
            AuthError: ``invalid_client`` for every failure (never cached).
        """
        cached = self._cache.get(url)
        if cached is not None and cached.expires > self.now():
            return cached.document
        try:
            document, ttl = await self._download(ctx, url)
            check_document(url, document)
        except CimdError as exc:
            self._cache.pop(url, None)
            raise oauth_error(
                "invalid_client", 401, f"client metadata: {exc}"
            ) from None
        self._cache[url] = _Cached(document, self.now() + ttl)
        return document

    async def _download(
        self, ctx: EndpointContext, url: str
    ) -> tuple[dict[str, Any], float]:  # Any: JSON
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or 443
        try:
            addresses = await asyncio.wait_for(self.resolver(host, port), _TIMEOUT)
        except (OSError, TimeoutError) as exc:
            raise CimdError("host not found") from exc
        if not addresses or not all(_public_ip(a) for a in addresses):
            # Every address must be public: one private answer could be chosen later.
            raise CimdError("host resolves to a non-public address")
        ip = addresses[0]
        netloc = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        target = f"https://{netloc}{parts.path}" + (
            f"?{parts.query}" if parts.query else ""
        )
        request = ctx.auth.http.build_request(
            "GET",
            target,
            headers={"host": parts.netloc, "accept": "application/json"},
            extensions={
                "sni_hostname": host,
                "timeout": {
                    "connect": _TIMEOUT,
                    "read": _TIMEOUT,
                    "write": _TIMEOUT,
                    "pool": _TIMEOUT,
                },
            },
        )
        try:
            async with asyncio.timeout(_TIMEOUT):
                response = await ctx.auth.http.send(
                    request, stream=True, follow_redirects=False
                )
                try:
                    if response.status_code != 200:
                        raise CimdError(f"HTTP {response.status_code}")
                    body = b""
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) > _MAX_DOCUMENT:
                            raise CimdError("document is larger than 5 KB")
                finally:
                    await response.aclose()
        except TimeoutError as exc:
            raise CimdError("timed out") from exc
        except httpx.HTTPError as exc:
            raise CimdError(f"request failed ({type(exc).__name__})") from exc
        try:
            document = json.loads(body)
        except ValueError as exc:
            raise CimdError("not JSON") from exc
        if not isinstance(document, dict):
            raise CimdError("not a JSON object")
        return cast(dict[str, Any], document), _ttl(
            response.headers.get("cache-control", "")
        )


def _ttl(cache_control: str) -> float:
    lowered = cache_control.lower()
    if "no-store" in lowered or "no-cache" in lowered:
        return _MIN_TTL
    match = _MAX_AGE.search(lowered)
    seconds = float(match.group(1)) if match else _DEFAULT_TTL
    return min(max(seconds, _MIN_TTL), _MAX_TTL)


def check_document(url: str, document: Mapping[str, Any]) -> None:  # Any: JSON
    """The CONTRACTS 12.3 rules for a client ID metadata document.

    Raises:
        CimdError: When a rule is broken.
    """
    if document.get("client_id") != url:
        raise CimdError("client_id does not equal the document URL")
    name = document.get("client_name")
    if not isinstance(name, str) or not name.strip():
        raise CimdError("client_name is required")
    uris = document.get("redirect_uris")
    if not isinstance(uris, list) or not uris:
        raise CimdError("redirect_uris is required")
    for uri in cast(list[object], uris):
        if not isinstance(uri, str) or not valid_redirect_uri(uri):
            raise CimdError("a redirect URI breaks the redirect rule")
    if "client_secret" in document or "client_secret_expires_at" in document:
        raise CimdError("a document must not carry a client secret")
    method = document.get("token_endpoint_auth_method")
    if method not in (None, "none"):
        raise CimdError(f"token_endpoint_auth_method {method!r} is not supported")
    grants = document.get("grant_types")
    if grants is not None and (
        not isinstance(grants, list)
        or not set(cast(list[object], grants))
        <= {"authorization_code", "refresh_token"}
    ):
        raise CimdError(
            "grant_types may only hold authorization_code and refresh_token"
        )


async def authenticate_client(
    ctx: EndpointContext,
    store: ClientStore,
    form: Mapping[str, Any],  # Any: form values
    *,
    require_confidential: bool = False,
) -> dict[str, Any]:  # Any: the client row
    """Client authentication: ``client_secret_basic``, ``client_secret_post`` or
    ``none`` (public clients).

    Raises:
        AuthError: ``invalid_client`` (401 with ``WWW-Authenticate``).
    """
    client_id = form.get("client_id")
    secret = form.get("client_secret")
    header = ctx.request.headers.get("authorization", "")
    if header[:6].lower() == "basic ":
        try:
            decoded = base64.b64decode(header[6:].strip(), validate=True).decode(
                "utf-8"
            )
            basic_id, _, basic_secret = decoded.partition(":")
            basic_id, basic_secret = unquote(basic_id), unquote(basic_secret)
        except (ValueError, UnicodeDecodeError):
            raise oauth_error("invalid_client", 401) from None
        if client_id is not None and client_id != basic_id:
            raise oauth_error("invalid_client", 401)
        client_id, secret = basic_id, basic_secret
    if not isinstance(client_id, str) or not client_id:
        raise oauth_error("invalid_client", 401)
    try:
        client = await store.get(ctx, client_id)
    except AuthError:
        raise
    if client is None or client.get("disabled_at") is not None:
        raise oauth_error("invalid_client", 401)
    if client["type"] == "confidential":
        stored = client.get("client_secret_hash")
        if (
            not isinstance(secret, str)
            or not stored
            or not ctx.crypto.equal(ctx.crypto.hash_token(secret), stored)
        ):
            raise oauth_error("invalid_client", 401)
    elif require_confidential or secret:
        raise oauth_error("invalid_client", 401)
    return client
