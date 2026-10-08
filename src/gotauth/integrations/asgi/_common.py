"""Helpers shared by the Starlette and Litestar adapters (no framework imports)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from typing import TYPE_CHECKING, Any, cast

from gotauth.contracts.errors import AuthError
from gotauth.contracts.http import AuthResponse
from gotauth.contracts.principal import Principal
from gotauth.core._http import body_bytes, error_response, set_cookie_header

if TYPE_CHECKING:
    from gotauth.contracts.config import GotAuthInstance as GotAuth

__all__ = [
    "COOKIES_KEY",
    "cookies_from",
    "error_payload",
    "headers_from",
    "missing_scopes",
    "pending_cookies",
    "resolve",
]


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


COOKIES_KEY = "gotauth.set_cookies"
"""Scope key holding the ``Set-Cookie`` values a sliding session refresh produced."""


async def resolve(
    auth: GotAuth,
    raw: Iterable[tuple[bytes, bytes]],
    scope: MutableMapping[str, Any] | None = None,
) -> Principal | None:
    """The request's principal, or ``None``.

    With only a session cookie, the session is read first through ``get_session`` so a
    sliding refresh's new cookie is kept: its ``Set-Cookie`` values go to
    ``scope[COOKIES_KEY]`` for the adapter to add to the response. Fails closed:
    unexpected errors become ``AuthError("INTERNAL_ERROR")``, never a principal.
    """
    headers = headers_from(raw)
    cookies = cookies_from(headers)
    try:
        bearer = headers.get("authorization", "")[:7].lower() == "bearer "
        if (
            scope is not None
            and not bearer
            and not headers.get("x-api-key")
            and cookies
        ):
            response = await auth.api.call(
                "get_session",
                headers={
                    k: v for k, v in headers.items() if k in ("cookie", "user-agent")
                },
                as_response=True,
            )
            if isinstance(response, AuthResponse) and response.cookies:
                stored = cast(list[str], scope.setdefault(COOKIES_KEY, []))
                stored.extend(set_cookie_header(c) for c in response.cookies)
        # Principal checks (bans) run here; the session was already slid above.
        return await auth.get_principal(headers, cookies)
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError("INTERNAL_ERROR", 500) from exc


def pending_cookies(scope: Mapping[str, Any]) -> list[bytes]:
    """The ``Set-Cookie`` header values to add to the response, encoded."""
    return [value.encode("latin-1") for value in scope.get(COOKIES_KEY, [])]


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
