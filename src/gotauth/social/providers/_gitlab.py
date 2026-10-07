"""GitLab, including self-hosted (OpenID Connect; checked against docs.gitlab.com on
2026-10-07)."""

from __future__ import annotations

from collections.abc import Sequence

from ._base import OidcProvider

__all__ = ["GitLabProvider"]


class GitLabProvider(OidcProvider):
    """GitLab.com or a self-hosted instance at ``base_url``."""

    id = "gitlab"
    name = "GitLab"

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        base_url: str = "https://gitlab.com",
        scopes: Sequence[str] = (),
        store_provider_tokens: bool = False,
    ) -> None:
        self.discovery_url = base_url.rstrip("/") + "/.well-known/openid-configuration"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            store_provider_tokens=store_provider_tokens,
        )
