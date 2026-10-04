"""An in-memory OAuth provider for social-login tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal
from urllib.parse import parse_qs, urlencode, urlsplit

from gotauth.contracts.errors import AuthError
from gotauth.contracts.social import ProviderTokens, ProviderUser

if TYPE_CHECKING:
    import httpx

__all__ = ["StubOAuthProvider", "fake_oauth_provider"]


@dataclass
class _Started:
    code_challenge: str
    redirect_uri: str
    scopes: tuple[str, ...]
    nonce: str | None


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class StubOAuthProvider:
    """A provider whose "users" are keyed by the authorization code a test picks.

    Flow in a test::

        provider = fake_oauth_provider(users={"code-1": ProviderUser(...)})
        url = provider.authorization_url(state=..., code_challenge=..., ...)
        query = provider.approve(state, "code-1")  # {"code": "code-1", "state": ...}
        # call the callback endpoint with query; exchange_code checks the PKCE verifier

    ``exchange_code`` raises ``AuthError("PROVIDER_ERROR")`` for an unknown code, a
    verifier that does not match the challenge seen in ``authorization_url``, or a
    different ``redirect_uri``. Implements ``FakeOAuthProvider``.
    """

    def __init__(
        self,
        id: str = "fake",
        *,
        users: Mapping[str, ProviderUser] | None = None,
        name: str = "Fake",
        default_scopes: tuple[str, ...] = ("openid", "email", "profile"),
        store_provider_tokens: bool = False,
        callback_method: Literal["GET", "POST"] = "GET",
    ) -> None:
        self.id = id
        self.name = name
        self.default_scopes = default_scopes
        self.store_provider_tokens = store_provider_tokens
        self.callback_method: Literal["GET", "POST"] = callback_method
        self.users: dict[str, ProviderUser] = dict(users or {})
        self.started: dict[str, _Started] = {}
        self.exchanged: list[str] = []
        self._codes: dict[str, str] = {}
        self._tokens: dict[str, str] = {}
        self._last_state: str | None = None

    def __repr__(self) -> str:
        return f"StubOAuthProvider(id={self.id!r}, users={len(self.users)})"

    def authorization_url(
        self,
        *,
        state: str,
        code_challenge: str,
        redirect_uri: str,
        scopes: Sequence[str],
        nonce: str | None,
    ) -> str:
        """Record the request and return a fake provider URL."""
        self.started[state] = _Started(
            code_challenge, redirect_uri, tuple(scopes), nonce
        )
        self._last_state = state
        query = {
            "client_id": "fake-client",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
        }
        if nonce is not None:
            query["nonce"] = nonce
        return f"https://{self.id}.oauth.test/authorize?{urlencode(query)}"

    def approve(self, state: str, code: str) -> dict[str, str]:
        """Bind ``code`` to the request started with ``state`` and return the callback
        query ``{"code", "state"}``. ``state`` may also be the authorization URL."""
        if state.startswith("https://"):
            state = parse_qs(urlsplit(state).query)["state"][0]
        if state not in self.started:
            msg = f"no authorization request was started with this state ({self.id})"
            raise LookupError(msg)
        self._codes[code] = state
        return {"code": code, "state": state}

    async def exchange_code(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> ProviderTokens:
        """Check the code, PKCE verifier and redirect URI, then return fake tokens."""
        state = self._codes.get(code, self._last_state)
        started = self.started.get(state) if state is not None else None
        if code not in self.users or started is None:
            raise AuthError("PROVIDER_ERROR", 502, "Unknown authorization code")
        if not hmac.compare_digest(_s256(code_verifier), started.code_challenge):
            raise AuthError("PROVIDER_ERROR", 502, "PKCE verification failed")
        if redirect_uri != started.redirect_uri:
            raise AuthError("PROVIDER_ERROR", 502, "redirect_uri mismatch")
        self.exchanged.append(code)
        access_token = f"fake-access-{len(self.exchanged)}"
        self._tokens[access_token] = code
        return ProviderTokens(
            access_token=access_token,
            refresh_token=None,
            id_token=None,
            expires_at=None,
            scope=" ".join(started.scopes),
        )

    async def get_user(
        self, http: httpx.AsyncClient, tokens: ProviderTokens, *, nonce: str | None
    ) -> ProviderUser:
        """Return the user bound to the code behind ``tokens``."""
        code = self._tokens.get(tokens.access_token)
        if code is None:
            raise AuthError("PROVIDER_ERROR", 502, "Unknown access token")
        return self.users[code]


def fake_oauth_provider(
    id: str = "fake",
    *,
    users: Mapping[str, ProviderUser] | None = None,
) -> StubOAuthProvider:
    """Return an in-memory provider; ``users`` maps authorization codes to users.

    It uses ``store_provider_tokens=False`` and ``callback_method="GET"``.
    """
    return StubOAuthProvider(id, users=users)
