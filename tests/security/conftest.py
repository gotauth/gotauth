"""A full GotAuth (every merged plugin) for the security tests."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from gotauth.contracts import ProviderUser
from gotauth.plugins.api_key import api_key
from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.testing import (
    fake_clock,
    fake_mailer,
    fake_oauth_provider,
    make_auth,
    make_client,
)

PASSWORD = "correct horse battery"
RESOURCE = "https://mcp.example.com/mcp"
REDIRECT = "https://app.example.com/cb"


@dataclass
class App:
    auth: Any  # Any: GotAuth
    mailer: Any  # Any: CapturingMailer
    clock: Any  # Any: ManualClock

    def client(self, *, origin: bool = True) -> httpx.AsyncClient:
        """``make_client``, optionally without its ``Origin`` header."""
        http = make_client(self.auth)
        if not origin:
            del http.headers["origin"]
        return http

    def last_token(self, kind: str, email: str = "ada@example.com") -> str:
        """The ``token`` query value of the newest email of a kind."""
        url = self.mailer.last(kind, email).data["url"]
        return parse_qs(urlsplit(url).query)["token"][0]

    async def verified_user(
        self, http: httpx.AsyncClient, email: str = "ada@example.com"
    ) -> None:
        """Sign up, verify through the emailed link and sign in (cookie set)."""
        await http.post("/sign-up/email", json={"email": email, "password": PASSWORD})
        await http.get(
            "/verify-email", params={"token": self.last_token("verify_email", email)}
        )
        response = await http.post(
            "/sign-in/email", json={"email": email, "password": PASSWORD}
        )
        assert response.status_code == 200, response.text


def full_app(**overrides: Any) -> App:
    """Every merged module: email + password, sessions, social, API keys, OAuth."""
    clock = overrides.pop("clock", None) or fake_clock()
    mailer = fake_mailer()
    options: dict[str, Any] = {
        "clock": clock,
        "mailer": mailer,
        "social_providers": [
            fake_oauth_provider(
                users={
                    "c1": ProviderUser(
                        id="gh-1",
                        email="ada@example.com",
                        email_verified=True,
                        name="Ada",
                        image=None,
                        raw={},
                    )
                }
            )
        ],
        "plugins": [
            api_key(allowed_scopes=["projects:read"]),
            oauth_provider(resources=[RESOURCE]),
        ],
    }
    options.update(overrides)
    return App(auth=make_auth(**options), mailer=mailer, clock=clock)


def pkce() -> tuple[str, str]:
    """A ``(verifier, S256 challenge)`` pair."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def oauth_client(app: App, kind: str = "public") -> tuple[str, str | None]:
    """Register a client for ``REDIRECT``: ``(client_id, client_secret)``."""
    created = await app.auth.api.call(
        "create_oauth_client",
        body={"name": "App", "type": kind, "redirect_uris": [REDIRECT]},
    )
    return created.client.client_id, created.client_secret


async def oauth_code(
    http: httpx.AsyncClient, client_id: str, **params: str
) -> tuple[str, str]:
    """Authorize and consent as the signed-in user: ``(code, verifier)``."""
    verifier, challenge = pkce()
    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "openid",
        **params,
    }
    screen = await http.get(
        "/oauth2/authorize", params=query, headers={"accept": "application/json"}
    )
    assert screen.status_code == 200, screen.text
    consent = await http.post(
        "/oauth2/consent",
        data={"consent_id": screen.json()["consent_id"], "accept": "true"},
    )
    code = parse_qs(urlsplit(consent.headers["location"]).query)["code"][0]
    return code, verifier


async def oauth_tokens(
    http: httpx.AsyncClient, client_id: str, code: str, verifier: str, **form: str
) -> httpx.Response:
    """Exchange a code at ``/oauth2/token``; ``form`` adds or overrides fields."""
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT,
        "client_id": client_id,
        **form,
    }
    return await http.post("/oauth2/token", data=body)
