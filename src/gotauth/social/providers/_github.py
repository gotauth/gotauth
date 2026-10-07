"""GitHub (OAuth 2; checked against docs.github.com on 2026-10-07)."""

from __future__ import annotations

from typing import Any, cast

import httpx

from gotauth.contracts.social import ProviderTokens, ProviderUser
from gotauth.social.oidc import fetch_json, provider_error

from ._base import OAuth2Provider

__all__ = ["GitHubProvider"]

_API = "https://api.github.com"


def _primary_verified(body: object) -> str | None:
    if not isinstance(body, list):
        return None
    for entry in cast("list[object]", body):
        if not isinstance(entry, dict):
            continue
        item = cast("dict[str, Any]", entry)
        email = item.get("email")
        if item.get("primary") is True and item.get("verified") is True:
            return email if isinstance(email, str) else None
    return None


class GitHubProvider(OAuth2Provider):
    """GitHub. The email is the primary, verified one from ``GET /user/emails``."""

    id = "github"
    name = "GitHub"
    default_scopes: tuple[str, ...] = ("read:user", "user:email")
    authorize_url = "https://github.com/login/oauth/authorize"
    token_url = "https://github.com/login/oauth/access_token"  # noqa: S105

    async def get_user(
        self, http: httpx.AsyncClient, tokens: ProviderTokens, *, nonce: str | None
    ) -> ProviderUser:
        """Return the GitHub user and their primary verified email."""
        headers = {
            "authorization": f"Bearer {tokens.access_token}",
            "accept": "application/vnd.github+json",
        }
        profile = await fetch_json(http, f"{_API}/user", headers=headers)
        if "id" not in profile:
            raise provider_error("no user id")
        try:
            response = await http.get(f"{_API}/user/emails", headers=headers)
            emails: object = response.json() if response.status_code < 400 else None
        except (httpx.HTTPError, ValueError) as exc:
            raise provider_error("email request failed") from exc
        email = _primary_verified(emails)
        return ProviderUser(
            id=str(profile["id"]),
            email=email,
            email_verified=email is not None,
            name=profile.get("name") or profile.get("login"),
            image=profile.get("avatar_url"),
            raw=profile,
        )
