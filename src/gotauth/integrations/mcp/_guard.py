"""The ASGI guard in front of an MCP endpoint: it builds every ``WWW-Authenticate``
challenge itself (CONTRACTS 12.4), because FastMCP and the MCP SDK both get them wrong.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from contextvars import ContextVar
from typing import Any, cast
from urllib.parse import urlsplit

from gotauth.integrations.mcp import _access
from gotauth.integrations.mcp._metadata import (
    advertised_scopes,
    insufficient_scope,
    invalid_token,
    metadata_path,
    metadata_url,
    missing_token,
    protected_resource_metadata,
)
from gotauth.integrations.mcp._verify import Verified, Verifier, VerifierUnavailable

__all__ = ["McpGuard", "ToolScopes", "verified_in_request"]

Scope = MutableMapping[str, Any]  # Any: ASGI
Message = MutableMapping[str, Any]  # Any: ASGI
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
App = Callable[[Scope, Receive, Send], Awaitable[None]]

ToolScopes = Callable[[Scope, str, Verified], Awaitable[Sequence[str]]]
"""``(scope, tool name, verified token) -> scopes the tool needs``."""

MAX_BODY = 4 * 1024 * 1024
"""The largest request body the guard reads to find tool calls."""

_verified: ContextVar[tuple[str, Verified] | None] = ContextVar(
    "gotauth_mcp_verified", default=None
)


def verified_in_request(token: str) -> Verified | None:
    """The guard's result for ``token`` in this request, so the framework's own token
    check does not verify it a second time."""
    found = _verified.get()
    return found[1] if found is not None and found[0] == token else None


def _route_path(scope: Scope) -> str:
    path = str(scope.get("path", ""))
    root = str(scope.get("root_path", ""))
    return path[len(root) :] if root and path.startswith(root) else path


def _bearer(scope: Scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"authorization":
            text = value.decode("latin-1")
            if text[:7].lower() == "bearer " and text[7:].strip():
                return text[7:].strip()
            return ""  # present but not a bearer token: invalid, not missing
    return None


async def _respond(
    send: Send,
    status: int,
    body: Any,  # Any: JSON, or None for an empty body
    headers: Sequence[tuple[bytes, bytes]] = (),
) -> None:
    content = b"" if body is None else json.dumps(body).encode()
    start: list[tuple[bytes, bytes]] = [(b"content-length", str(len(content)).encode())]
    if body is not None:
        start.append((b"content-type", b"application/json"))
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [*start, *headers],
        }
    )
    await send({"type": "http.response.body", "body": content})


def _called_tools(body: bytes) -> list[str]:
    try:
        message = json.loads(body)
    except ValueError:
        return []
    batch = cast(list[Any], message) if isinstance(message, list) else [message]
    names: list[str] = []
    for item in batch:
        request = cast(dict[str, Any], item) if isinstance(item, dict) else {}
        if request.get("method") == "tools/call":
            params = request.get("params")
            found = cast(dict[str, Any], params) if isinstance(params, dict) else {}
            name = found.get("name")
            if isinstance(name, str):
                names.append(name)
    return names


class McpGuard:
    """Protects one MCP endpoint and serves its RFC 9728 metadata.

    - No token: 401 with ``resource_metadata`` and the configured scopes.
    - A bad, expired or revoked token: the same with ``error="invalid_token"``.
    - A token without a configured scope, or without a scope the called tool needs:
      403 ``insufficient_scope`` naming every scope the call needs.
    - The authorization server unreachable (remote verification): 503.
    """

    def __init__(
        self,
        app: App,
        *,
        verifier: Verifier,
        scopes: Sequence[str],
        path: str | Callable[[], str | None] | None = None,
        tool_scopes: ToolScopes | None = None,
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.scopes = advertised_scopes(scopes)
        self._path = path
        self._tool_scopes = tool_scopes
        resource = verifier.resource
        self.metadata_url = metadata_url(resource)
        self._metadata_path = metadata_path(resource)
        self._metadata = json.dumps(
            protected_resource_metadata(
                resource=resource, issuer=verifier.issuer, scopes=scopes
            )
        ).encode()

    def _protected_path(self) -> str:
        path = self._path() if callable(self._path) else self._path
        if path is None:
            path = urlsplit(self.verifier.resource).path or "/"
        return path.rstrip("/") or "/"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        route = _route_path(scope).rstrip("/") or "/"
        if route == self._metadata_path and scope.get("method") in ("GET", "HEAD"):
            await self.serve_metadata(send)
            return
        if route != self._protected_path() or scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return
        token = _bearer(scope)
        if token is None:
            header = missing_token(self.metadata_url, self.scopes)
            await _respond(send, 401, None, [(b"www-authenticate", header.encode())])
            return
        try:
            verified = await self.verifier.verify(token) if token else None
        except VerifierUnavailable:
            await _respond(send, 503, {"error": "temporarily_unavailable"})
            return
        if verified is None:
            header = invalid_token(self.metadata_url, self.scopes)
            await _respond(
                send,
                401,
                {"error": "invalid_token"},
                [(b"www-authenticate", header.encode())],
            )
            return
        needed = list(self.scopes)
        if self._tool_scopes is not None and scope.get("method") == "POST":
            body = await self._read_body(receive)
            if body is None:
                await _respond(send, 413, {"error": "request_too_large"})
                return
            for name in _called_tools(body):
                needed.extend(await self._tool_scopes(scope, name, verified))
            receive = _replay(body, receive)
        needed = list(dict.fromkeys(needed))
        if not set(needed) <= verified.access.scopes:
            header = insufficient_scope(self.metadata_url, needed)
            await _respond(
                send,
                403,
                {"error": "insufficient_scope"},
                [(b"www-authenticate", header.encode())],
            )
            return
        access_token = _access.current.set(verified.access)
        verified_token = _verified.set((token, verified))
        try:
            await self.app(scope, receive, send)
        finally:
            _verified.reset(verified_token)
            _access.current.reset(access_token)

    async def serve_metadata(self, send: Send) -> None:
        """Answer with the RFC 9728 document; any origin may read it."""
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(self._metadata)).encode()),
                    (b"access-control-allow-origin", b"*"),
                    (b"cache-control", b"public, max-age=3600"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": self._metadata})

    @staticmethod
    async def _read_body(receive: Receive) -> bytes | None:
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunk = cast(bytes, message.get("body", b""))
            size += len(chunk)
            if size > MAX_BODY:
                return None
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        return b"".join(chunks)


def _replay(body: bytes, receive: Receive) -> Receive:
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay
