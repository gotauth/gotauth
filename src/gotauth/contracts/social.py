"""CONTRACTS section 11: social login providers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:
    import httpx

__all__ = ["FakeOAuthProvider", "OAuthProvider", "ProviderTokens", "ProviderUser"]


@dataclass(frozen=True)
class ProviderTokens:
    """Tokens from a provider's token endpoint. Left out of ``repr()``."""

    access_token: str = dc_field(repr=False)
    refresh_token: str | None = dc_field(repr=False)
    id_token: str | None = dc_field(repr=False)
    expires_at: datetime | None
    scope: str | None


@dataclass(frozen=True)
class ProviderUser:
    """The user as the provider describes them."""

    id: str
    email: str | None
    email_verified: bool
    name: str | None
    image: str | None
    # Any: the provider's raw profile JSON.
    raw: Mapping[str, Any] = dc_field(repr=False)


class OAuthProvider(Protocol):
    """An OAuth 2 / OIDC identity provider (C4 ships the real ones)."""

    id: str
    """Provider id used in paths, e.g. ``"github"``."""
    name: str
    """Display name, e.g. ``"GitHub"``."""
    default_scopes: tuple[str, ...]
    store_provider_tokens: bool
    """Factory keyword, default False."""
    callback_method: Literal["GET", "POST"]
    """``"POST"`` only for form_post providers (Apple)."""

    def authorization_url(
        self,
        *,
        state: str,
        code_challenge: str,
        redirect_uri: str,
        scopes: Sequence[str],
        nonce: str | None,
    ) -> str:
        """Return the provider URL the browser is sent to."""
        ...

    async def exchange_code(
        self,
        http: httpx.AsyncClient,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> ProviderTokens:
        """Exchange an authorization code (with its PKCE verifier) for tokens."""
        ...

    async def get_user(
        self, http: httpx.AsyncClient, tokens: ProviderTokens, *, nonce: str | None
    ) -> ProviderUser:
        """Return the user behind the tokens."""
        ...


class FakeOAuthProvider(OAuthProvider, Protocol):
    """An in-memory provider for tests (``gotauth.testing.fake_oauth_provider``).

    ``users`` is keyed by authorization code: a test picks the code the "provider"
    returns to the callback.
    """

    users: dict[str, ProviderUser]

    def approve(self, state: str, code: str) -> dict[str, str]:
        """Simulate the user approving the request started with ``state``.

        Binds ``code`` to the PKCE challenge seen for that state and returns the
        callback query parameters ``{"code": ..., "state": ...}``.
        """
        ...
