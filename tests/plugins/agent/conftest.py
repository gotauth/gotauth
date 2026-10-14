"""Helpers for the agent plugin tests: a GotAuth with API keys, the OAuth server and
agents, two signed-in users, and the OAuth code flow."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from gotauth.plugins.agent import agent
from gotauth.plugins.api_key import api_key
from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.testing import fake_clock, make_auth, make_client

PASSWORD = "correct horse battery"
REDIRECT = "https://app.example.com/callback"
SCOPES = ("openid", "projects:read", "offline_access")


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass
class World:
    auth: Any  # Any: GotAuth
    ada: httpx.AsyncClient
    bob: httpx.AsyncClient
    ada_id: str
    bob_id: str
    clock: Any  # Any: ManualClock

    async def new_agent(self, name: str = "Helper") -> dict[str, Any]:  # Any: JSON
        response = await self.ada.post("/agents", json={"name": name})
        assert response.status_code == 200, response.text
        return response.json()

    async def agent_key(self, agent_id: str) -> str:
        response = await self.ada.post(
            f"/agents/{agent_id}/api-keys",
            json={"name": "k", "scopes": ["projects:read"]},
        )
        assert response.status_code == 200, response.text
        return str(response.json()["key"])

    async def key_principal(self, key: str) -> Any:  # Any: Principal or None
        out = await self.auth.api.call("verify_api_key", body={"key": key})
        return out.principal if out.valid else None

    async def client(self, owner: str | None = None) -> str:
        created = await self.auth.api.call(
            "create_oauth_client",
            body={
                "name": "Agent client",
                "type": "public",
                "redirect_uris": [REDIRECT],
                "scopes": list(SCOPES),
                "owner_user_id": owner or self.ada_id,
            },
        )
        return str(created.client.client_id)

    async def tokens(self, client_id: str) -> dict[str, Any]:  # Any: JSON
        """Ada's code flow for ``client_id``; the token response."""
        verifier, challenge = pkce()
        first = await self.ada.get(
            "/oauth2/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT,
                "scope": "openid projects:read offline_access",
                "state": "s",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            headers={"accept": "application/json"},
        )
        if first.status_code == 302:
            location = first.headers["location"]
        else:
            assert first.status_code == 200, first.text
            consent = await self.ada.post(
                "/oauth2/consent",
                data={"consent_id": first.json()["consent_id"], "accept": "true"},
            )
            location = consent.headers["location"]
        code = parse_qs(urlsplit(location).query)["code"][0]
        response = await self.ada.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": verifier,
                "client_id": client_id,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()

    async def token_principal(self, token: str) -> Any:  # Any: Principal or None
        out = await self.auth.api.call("verify_access_token", body={"token": token})
        return out.principal if out.valid else None


async def world(**options: Any) -> World:
    clock = fake_clock()
    plugins = options.pop(
        "plugins",
        [
            api_key(allowed_scopes=["projects:read"]),
            oauth_provider(scopes=SCOPES),
            agent(),
        ],
    )
    auth = make_auth(
        clock=clock,
        email_password={"require_email_verification": False},
        plugins=plugins,
        **options,
    )
    ids: list[str] = []
    clients: list[httpx.AsyncClient] = []
    for email in ("ada@example.com", "bob@example.com"):
        http = make_client(auth)
        signed_up = await http.post(
            "/sign-up/email", json={"email": email, "password": PASSWORD}
        )
        assert signed_up.status_code == 200, signed_up.text
        ids.append(signed_up.json()["user"]["id"])
        clients.append(http)
    return World(
        auth=auth,
        ada=clients[0],
        bob=clients[1],
        ada_id=ids[0],
        bob_id=ids[1],
        clock=clock,
    )
