"""Helpers for the MCP integration tests: a GotAuth with the OAuth server, tokens from
its real code flow, and MCP calls over in-process HTTP."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.testing import fake_clock, make_auth, make_client

PASSWORD = "correct horse battery"
REDIRECT = "https://app.example.com/callback"
RESOURCE = "http://localhost:8000/mcp"
ISSUER = "http://localhost:8000/api/auth"
OTHER = "http://localhost:8000/other"
METADATA = "http://localhost:8000/.well-known/oauth-protected-resource/mcp"
SCOPES = ("openid", "projects:read", "projects:write", "offline_access")


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass
class Issuer:
    """A GotAuth with ``oauth_provider(mcp=True)``, a signed-in user and a client."""

    auth: Any  # Any: GotAuth
    http: httpx.AsyncClient
    clock: Any  # Any: ManualClock
    client_id: str
    client_secret: str | None

    async def token(
        self, scope: str = "projects:read", resource: str = RESOURCE
    ) -> str:
        verifier, challenge = _pkce()
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": REDIRECT,
            "scope": scope,
            "state": "s",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource,
        }
        first = await self.http.get(
            "/oauth2/authorize", params=query, headers={"accept": "application/json"}
        )
        if first.status_code == 302:
            location = first.headers["location"]
        else:
            assert first.status_code == 200, first.text
            consent = await self.http.post(
                "/oauth2/consent",
                data={"consent_id": first.json()["consent_id"], "accept": "true"},
            )
            location = consent.headers["location"]
        code = parse_qs(urlsplit(location).query)["code"][0]
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
            "client_id": self.client_id,
        }
        if self.client_secret:
            form["client_secret"] = self.client_secret
        tokens = await self.http.post("/oauth2/token", data=form)
        assert tokens.status_code == 200, tokens.text
        return str(tokens.json()["access_token"])


async def issuer(*, confidential: bool = False) -> Issuer:
    # Real time: the frameworks check exp against the system clock too.
    clock = fake_clock(datetime.now(UTC).replace(microsecond=0))
    auth = make_auth(
        clock=clock,
        email_password={"require_email_verification": False},
        plugins=[oauth_provider(mcp=True, resources=[RESOURCE, OTHER], scopes=SCOPES)],
    )
    http = make_client(auth)
    signed_up = await http.post(
        "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
    )
    assert signed_up.status_code == 200, signed_up.text
    spec: dict[str, Any] = {
        "name": "MCP client",
        "type": "confidential" if confidential else "public",
        "redirect_uris": [REDIRECT],
        "scopes": list(SCOPES),
    }
    if confidential:
        spec["grant_types"] = [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ]
    created = await auth.api.call("create_oauth_client", body=spec)
    return Issuer(
        auth=auth,
        http=http,
        clock=clock,
        client_id=created.client.client_id,
        client_secret=created.client_secret,
    )


@asynccontextmanager
async def mcp_client(
    app: Any,  # Any: an ASGI app
    lifespan: Any = None,  # Any: the Starlette app whose lifespan runs, if not app
) -> AsyncIterator[httpx.AsyncClient]:
    """An HTTP client for an MCP app, with its lifespan running."""
    starlette = lifespan or app
    async with (
        starlette.router.lifespan_context(starlette),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000"
        ) as http,
    ):
        yield http


def call(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """A stateless ``tools/call`` request body."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


async def post(
    http: httpx.AsyncClient, body: dict[str, Any], token: str | None = None
) -> httpx.Response:
    headers = {"accept": "application/json, text/event-stream"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    return await http.post("/mcp", json=body, headers=headers)
