"""Pure ASGI serving, without any web framework (CONTRACTS 4)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qsl

from gotauth.contracts.errors import AuthError
from gotauth.contracts.http import (
    ASGIReceive,
    ASGIScope,
    ASGISend,
    AuthRequest,
    AuthResponse,
)
from gotauth.contracts.protection import resolve_client_ip
from gotauth.core._http import body_bytes, error_response, set_cookie_header

if TYPE_CHECKING:
    from gotauth.core._auth import GotAuth

__all__ = ["MAX_BODY_BYTES", "AsgiApp"]

MAX_BODY_BYTES = 1024 * 1024


class _TooLarge(Exception):
    pass


class AsgiApp:
    """An ASGI app over ``GotAuth``: the auth mount, or the host-root well-known app."""

    def __init__(self, auth: GotAuth, *, well_known: bool) -> None:
        self._auth = auth
        self._well_known = well_known

    async def __call__(
        self, scope: ASGIScope, receive: ASGIReceive, send: ASGISend
    ) -> None:
        """Serve one HTTP request; lifespan messages are acknowledged."""
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        try:
            request = await self._request(scope, receive)
        except _TooLarge:
            await self._send(
                send,
                error_response(
                    AuthError("INVALID_REQUEST", 413, "Body is too large"), "gotauth"
                ),
            )
            return
        if self._well_known:
            response = await self._auth.handle_well_known(request)
        else:
            response = await self._auth.handle(request)
        await self._send(send, response)

    async def _lifespan(self, receive: ASGIReceive, send: ASGISend) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await self._auth.drain()
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _request(self, scope: ASGIScope, receive: ASGIReceive) -> AuthRequest:
        config = self._auth.config
        path: str = scope.get("path", "/") or "/"
        root = scope.get("root_path", "") or ""
        if root and path.startswith(root):
            path = path[len(root) :] or "/"
        elif not self._well_known:
            base = config.base_path.rstrip("/")
            if base and path.startswith(base + "/"):
                path = path[len(base) :]
        headers: dict[str, str] = {}
        for raw_name, raw_value in scope.get("headers", []):
            name = bytes(raw_name).decode("latin-1").lower()
            value = bytes(raw_value).decode("latin-1")
            headers[name] = (
                f"{headers[name]}, {value}"
                if name in headers and name != "cookie"
                else (f"{headers[name]}; {value}" if name in headers else value)
            )
        query_string = bytes(scope.get("query_string", b"")).decode("latin-1")
        query = dict(parse_qsl(query_string, keep_blank_values=True))
        body = b""
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            body += message.get("body", b"")
            if len(body) > MAX_BODY_BYTES:
                raise _TooLarge
            more = bool(message.get("more_body", False))
        client = scope.get("client")
        peer = client[0] if client else None
        prefix = "" if self._well_known else config.base_path.rstrip("/")
        url = (
            config.base_url
            + prefix
            + path
            + (f"?{query_string}" if query_string else "")
        )
        return AuthRequest(
            method=str(scope.get("method", "GET")).upper(),
            path=path,
            url=url,
            query=query,
            headers=headers,
            cookies=_cookies(headers.get("cookie", "")),
            body=body,
            client_ip=resolve_client_ip(peer, headers, config),
        )

    @staticmethod
    async def _send(send: ASGISend, response: AuthResponse) -> None:
        status = response.status
        raw_headers: list[tuple[bytes, bytes]] = []
        payload = b""
        if response.redirect is not None:
            status = 302 if status == 200 else status
            raw_headers.append((b"location", response.redirect.encode("latin-1")))
        else:
            payload, content_type = body_bytes(response)
            raw_headers.append((b"content-type", content_type.encode()))
        for name, value in response.headers.items():
            raw_headers.append(
                (name.lower().encode("latin-1"), value.encode("latin-1"))
            )
        for cookie in response.cookies:
            raw_headers.append(
                (b"set-cookie", set_cookie_header(cookie).encode("latin-1"))
            )
        raw_headers.append((b"content-length", str(len(payload)).encode()))
        await send(
            {"type": "http.response.start", "status": status, "headers": raw_headers}
        )
        await send({"type": "http.response.body", "body": payload})


def _cookies(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in header.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            cookies.setdefault(name, value)
    return cookies
