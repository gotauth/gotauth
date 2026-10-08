"""Helpers shared by the Starlette and Litestar adapters (no framework imports)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from gotauth.contracts.errors import AuthError
from gotauth.contracts.principal import Principal
from gotauth.core._http import body_bytes, error_response

if TYPE_CHECKING:
    from gotauth.contracts.config import GotAuthInstance as GotAuth

__all__ = ["cookies_from", "error_payload", "headers_from", "missing_scopes", "resolve"]


def headers_from(raw: Iterable[tuple[bytes, bytes]]) -> dict[str, str]:
    """Lower-case headers from an ASGI scope; repeats joined as the core does."""
    headers: dict[str, str] = {}
    for raw_name, raw_value in raw:
        name = bytes(raw_name).decode("latin-1").lower()
        value = bytes(raw_value).decode("latin-1")
        if name in headers:
            separator = "; " if name == "cookie" else ", "
            headers[name] = f"{headers[name]}{separator}{value}"
        else:
            headers[name] = value
    return headers


def cookies_from(headers: dict[str, str]) -> dict[str, str]:
    """Parse the Cookie header (first value of a name wins)."""
    cookies: dict[str, str] = {}
    for part in headers.get("cookie", "").split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            cookies.setdefault(name, value)
    return cookies


async def resolve(
    auth: GotAuth, raw: Iterable[tuple[bytes, bytes]]
) -> Principal | None:
    """The request's principal, or ``None``. Fails closed: unexpected errors become
    ``AuthError("INTERNAL_ERROR")``, never a principal."""
    headers = headers_from(raw)
    try:
        return await auth.get_principal(headers, cookies_from(headers))
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError("INTERNAL_ERROR", 500) from exc


def missing_scopes(principal: Principal, scopes: tuple[str, ...]) -> list[str]:
    """Scopes the principal lacks; sessions (``scopes=None``) lack none."""
    if principal.has_scopes(*scopes):
        return []
    return sorted(set(scopes) - (principal.scopes or frozenset()))


def error_payload(error: AuthError) -> tuple[int, bytes, dict[str, str]]:
    """Status, JSON body and headers of a GotAuth error (section 6)."""
    response = error_response(error, "gotauth")
    payload, content_type = body_bytes(response)
    headers = {**response.headers, "content-type": content_type}
    if error.status == 401:
        headers.setdefault("www-authenticate", "Bearer")
    return response.status, payload, headers
