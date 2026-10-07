"""Shared OAuth 2 and OpenID Connect provider code."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar, Literal
from urllib.parse import urlencode

import httpx

from gotauth.contracts.social import ProviderTokens, ProviderUser
from gotauth.social.oidc import (
    DiscoveryCache,
    JwksCache,
    fetch_json,
    provider_error,
    verify_id_token,
)

__all__ = ["OAuth2Provider", "OidcProvider", "as_bool"]


def as_bool(value: object) -> bool:
    """Read a boolean claim; some providers send ``"true"`` as a string."""
    return value is True or (isinstance(value, str) and value.lower() == "true")


class OAuth2Provider:
    """An OAuth 2 provider with PKCE and ``client_secret_post`` authentication."""

    id: str = ""
    name: str = ""
    default_scopes: tuple[str, ...] = ()
    callback_method: Literal["GET", "POST"] = "GET"
    authorize_url: str = ""
    token_url: str = ""
    extra_authorize_params: ClassVar[Mapping[str, str]] = {}

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str] = (),
        store_provider_tokens: bool = False,
    ) -> None:
        self.client_id = client_id
        self._client_secret = client_secret
        self.store_provider_tokens = store_provider_tokens
        if scopes:
            self.default_scopes = tuple(scopes)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(id={self.id!r}, client_id={self.client_id!r})"

    def _authorize_endpoint(self) -> str:
        return self.authorize_url

    def authorization_url(
        self,
        *,
        state: str,
        code_challenge: str,
        redirect_uri: str,
        scopes: Sequence[str],
        nonce: str | None,
    ) -> str:
        """Return the URL the browser is sent to."""
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            **self.extra_authorize_params,
        }
        if nonce is not None:
            query["nonce"] = nonce
        return f"{self._authorize_endpoint()}?{urlencode(query)}"

    async def _token_endpoint(self, http: httpx.AsyncClient) -> str:
        del http
        return self.token_url

    async def exchange_code(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> ProviderTokens:
        """Exchange the code (with the PKCE verifier) for tokens."""
        body = await fetch_json(
            http,
            await self._token_endpoint(http),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
                "client_id": self.client_id,
                "client_secret": self._client_secret,
            },
            headers={"accept": "application/json"},
        )
        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise provider_error(str(body.get("error", "no access token")))
        expires_in = body.get("expires_in")
        expires_at = (
            datetime.now(UTC) + timedelta(seconds=int(expires_in))
            if isinstance(expires_in, int | str) and str(expires_in).isdigit()
            else None
        )
        return ProviderTokens(
            access_token=access_token,
            refresh_token=body.get("refresh_token"),
            id_token=body.get("id_token"),
            expires_at=expires_at,
            scope=body.get("scope"),
        )

    async def get_user(
        self, http: httpx.AsyncClient, tokens: ProviderTokens, *, nonce: str | None
    ) -> ProviderUser:
        """Return the user behind the tokens."""
        raise NotImplementedError


class OidcProvider(OAuth2Provider):
    """An OpenID Connect provider: the user comes from a verified ID token."""

    default_scopes: tuple[str, ...] = ("openid", "email", "profile")
    discovery_url: str = ""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str] = (),
        store_provider_tokens: bool = False,
    ) -> None:
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            store_provider_tokens=store_provider_tokens,
        )
        self._discovery = DiscoveryCache(self.discovery_url)
        self._jwks: JwksCache | None = None
        self._authorize_cached: str | None = None

    def _authorize_endpoint(self) -> str:
        if self.authorize_url:
            return self.authorize_url
        if self._authorize_cached is None:
            msg = "call prepare() before authorization_url()"
            raise RuntimeError(msg)
        return self._authorize_cached

    async def prepare(self, http: httpx.AsyncClient) -> None:
        """Load discovery, so ``authorization_url`` knows the endpoint."""
        if not self.authorize_url:
            self._authorize_cached = (
                await self._discovery.get(http)
            ).authorization_endpoint

    async def _token_endpoint(self, http: httpx.AsyncClient) -> str:
        if self.token_url:
            return self.token_url
        return (await self._discovery.get(http)).token_endpoint

    def _issuer_check(self, issuer: str) -> str | Callable[[Mapping[str, Any]], bool]:
        return issuer

    async def claims(
        self, http: httpx.AsyncClient, tokens: ProviderTokens, *, nonce: str | None
    ) -> dict[str, Any]:  # Any: JWT claims
        """Verify the ID token and return its claims."""
        if not tokens.id_token:
            raise provider_error("no ID token")
        discovery = await self._discovery.get(http)
        if self._jwks is None or self._jwks.url != discovery.jwks_uri:
            self._jwks = JwksCache(discovery.jwks_uri)
        return await verify_id_token(
            http,
            tokens.id_token,
            jwks=self._jwks,
            audience=self.client_id,
            issuer=self._issuer_check(discovery.issuer),
            nonce=nonce,
            algorithms=discovery.algorithms,
        )

    def user_from_claims(self, claims: Mapping[str, Any]) -> ProviderUser:
        """Map ID token claims to a ``ProviderUser``."""
        email = claims.get("email")
        return ProviderUser(
            id=str(claims["sub"]),
            email=email if isinstance(email, str) else None,
            email_verified=as_bool(claims.get("email_verified")),
            name=claims.get("name"),
            image=claims.get("picture"),
            raw=dict(claims),
        )

    async def get_user(
        self, http: httpx.AsyncClient, tokens: ProviderTokens, *, nonce: str | None
    ) -> ProviderUser:
        """Return the user from the verified ID token."""
        return self.user_from_claims(await self.claims(http, tokens, nonce=nonce))
