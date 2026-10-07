"""Discord (OAuth 2; checked against discord.com/developers on 2026-10-07)."""

from __future__ import annotations

import httpx

from gotauth.contracts.social import ProviderTokens, ProviderUser
from gotauth.social.oidc import fetch_json, provider_error

from ._base import OAuth2Provider

__all__ = ["DiscordProvider"]


class DiscordProvider(OAuth2Provider):
    """Discord; the email is verified when ``verified`` is true."""

    id = "discord"
    name = "Discord"
    default_scopes: tuple[str, ...] = ("identify", "email")
    authorize_url = "https://discord.com/oauth2/authorize"
    token_url = "https://discord.com/api/oauth2/token"  # noqa: S105

    async def get_user(
        self, http: httpx.AsyncClient, tokens: ProviderTokens, *, nonce: str | None
    ) -> ProviderUser:
        """Return the Discord user."""
        body = await fetch_json(
            http,
            "https://discord.com/api/users/@me",
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        if "id" not in body:
            raise provider_error("no user id")
        user_id = str(body["id"])
        avatar = body.get("avatar")
        image = (
            f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png"
            if isinstance(avatar, str)
            else None
        )
        email = body.get("email")
        return ProviderUser(
            id=user_id,
            email=email if isinstance(email, str) else None,
            email_verified=body.get("verified") is True,
            name=body.get("global_name") or body.get("username"),
            image=image,
            raw=body,
        )
