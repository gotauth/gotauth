"""Provider classes. Use the factories in ``gotauth.social`` instead."""

from __future__ import annotations

from ._apple import AppleProvider
from ._base import OAuth2Provider, OidcProvider
from ._discord import DiscordProvider
from ._generic import GenericOidcProvider
from ._github import GitHubProvider
from ._gitlab import GitLabProvider
from ._google import GoogleProvider
from ._microsoft import MicrosoftProvider

__all__ = [
    "AppleProvider",
    "DiscordProvider",
    "GenericOidcProvider",
    "GitHubProvider",
    "GitLabProvider",
    "GoogleProvider",
    "MicrosoftProvider",
    "OAuth2Provider",
    "OidcProvider",
]
