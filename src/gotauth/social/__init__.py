"""Social sign-in and account linking with OAuth 2 and OpenID Connect providers (C4).

Pass providers to ``GotAuth(social_providers=[github(...), google(...)])``. See
README.md for the linking rules.
"""

from __future__ import annotations

from collections.abc import Sequence

from ._plugin import (
    CallbackIn,
    LinkSocialIn,
    SignInSocialIn,
    UnlinkAccountIn,
    social_plugin,
)
from .providers import (
    AppleProvider,
    DiscordProvider,
    GenericOidcProvider,
    GitHubProvider,
    GitLabProvider,
    GoogleProvider,
    MicrosoftProvider,
)

__all__ = [
    "CallbackIn",
    "LinkSocialIn",
    "SignInSocialIn",
    "UnlinkAccountIn",
    "apple",
    "discord",
    "generic_oidc",
    "github",
    "gitlab",
    "google",
    "microsoft",
    "social_plugin",
]


def github(
    *,
    client_id: str,
    client_secret: str,
    scopes: Sequence[str] = (),
    store_provider_tokens: bool = False,
) -> GitHubProvider:
    """Return the GitHub provider."""
    return GitHubProvider(
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        store_provider_tokens=store_provider_tokens,
    )


def google(
    *,
    client_id: str,
    client_secret: str,
    scopes: Sequence[str] = (),
    store_provider_tokens: bool = False,
) -> GoogleProvider:
    """Return the Google provider."""
    return GoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        store_provider_tokens=store_provider_tokens,
    )


def microsoft(
    *,
    client_id: str,
    client_secret: str,
    tenant: str = "common",
    scopes: Sequence[str] = (),
    store_provider_tokens: bool = False,
) -> MicrosoftProvider:
    """Return the Microsoft provider for a tenant id or ``common``."""
    return MicrosoftProvider(
        client_id=client_id,
        client_secret=client_secret,
        tenant=tenant,
        scopes=scopes,
        store_provider_tokens=store_provider_tokens,
    )


def discord(
    *,
    client_id: str,
    client_secret: str,
    scopes: Sequence[str] = (),
    store_provider_tokens: bool = False,
) -> DiscordProvider:
    """Return the Discord provider."""
    return DiscordProvider(
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        store_provider_tokens=store_provider_tokens,
    )


def gitlab(
    *,
    client_id: str,
    client_secret: str,
    base_url: str = "https://gitlab.com",
    scopes: Sequence[str] = (),
    store_provider_tokens: bool = False,
) -> GitLabProvider:
    """Return the GitLab provider; ``base_url`` for self-hosted instances."""
    return GitLabProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        scopes=scopes,
        store_provider_tokens=store_provider_tokens,
    )


def apple(
    *,
    client_id: str,
    client_secret: str,
    scopes: Sequence[str] = (),
    store_provider_tokens: bool = False,
) -> AppleProvider:
    """Return the Apple provider; ``client_secret`` is Apple's client-secret JWT."""
    return AppleProvider(
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        store_provider_tokens=store_provider_tokens,
    )


def generic_oidc(
    id: str,
    discovery_url: str,
    *,
    client_id: str,
    client_secret: str,
    name: str | None = None,
    scopes: Sequence[str] = (),
    store_provider_tokens: bool = False,
) -> GenericOidcProvider:
    """Return a provider for any OpenID Connect issuer."""
    return GenericOidcProvider(
        id,
        discovery_url,
        client_id=client_id,
        client_secret=client_secret,
        name=name,
        scopes=scopes,
        store_provider_tokens=store_provider_tokens,
    )
