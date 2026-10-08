"""Helpers for the OAuth server tests: a GotAuth with the plugin, a signed-in browser
and the authorization code + PKCE steps."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.testing import fake_clock, make_auth, make_client

PASSWORD = "correct horse battery"
REDIRECT = "https://app.example.com/callback"
RESOURCE = "https://mcp.example.com/mcp"
ISSUER = "http://localhost:8000/api/auth"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def query_of(location: str) -> dict[str, str]:
    return {
        key: values[0] for key, values in parse_qs(urlsplit(location).query).items()
    }


@dataclass
class World:
    auth: Any  # Any: GotAuth
    http: httpx.AsyncClient
    clock: Any  # Any: ManualClock
    client_id: str = ""
    client_secret: str | None = None
    extra: dict[str, Any] = field(default_factory=dict[str, Any])

    async def authorize(self, **params: str) -> httpx.Response:
        verifier, challenge = pkce()
        self.extra["verifier"] = verifier
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": REDIRECT,
            "scope": "openid profile email",
            "state": "st-1",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        query.update(params)
        return await self.http.get(
            "/oauth2/authorize",
            params={k: v for k, v in query.items() if v != ""},
            headers={"accept": "application/json"},
        )

    async def consent(
        self, consent_id: str, accept: str = "true", **extra: str
    ) -> httpx.Response:
        return await self.http.post(
            "/oauth2/consent",
            data={"consent_id": consent_id, "accept": accept, **extra},
        )

    async def code(self, **params: str) -> str:
        """Run authorize and consent; return the code."""
        first = await self.authorize(**params)
        if first.status_code == 302:
            location = first.headers["location"]
        else:
            assert first.status_code == 200, first.text
            location = (await self.consent(first.json()["consent_id"])).headers[
                "location"
            ]
        values = query_of(location)
        assert "code" in values, values
        return values["code"]

    async def token(self, **form: str) -> httpx.Response:
        body = {"client_id": self.client_id, **form}
        if self.client_secret:
            body["client_secret"] = self.client_secret
        return await self.http.post("/oauth2/token", data=body)

    async def exchange(self, code: str, **form: str) -> httpx.Response:
        return await self.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=form.pop("redirect_uri", REDIRECT),
            code_verifier=form.pop("code_verifier", self.extra["verifier"]),
            **form,
        )


async def world(
    *, client: dict[str, Any] | None = None, sign_in: bool = True, **options: Any
) -> World:
    clock = fake_clock()
    options.setdefault("resources", [RESOURCE])
    auth = make_auth(
        clock=clock,
        email_password={"require_email_verification": False},
        plugins=[oauth_provider(**options)],
    )
    http = make_client(auth)
    if sign_in:
        response = await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        assert response.status_code == 200, response.text
    w = World(auth=auth, http=http, clock=clock)
    spec: dict[str, Any] = {
        "name": "Example App",
        "type": "public",
        "redirect_uris": [REDIRECT],
    }
    spec.update(client or {})
    created = await auth.api.call("create_oauth_client", body=spec)
    w.client_id = created.client.client_id
    w.client_secret = created.client_secret
    return w
