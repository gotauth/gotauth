"""All of this app's auth configuration."""

from __future__ import annotations

import os
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import create_async_engine

from gotauth import GotAuth
from gotauth.contracts import Adapter, EmailSender, OAuthProvider
from gotauth.plugins.api_key import api_key
from gotauth.plugins.organization import organization
from gotauth.plugins.passkey import passkey
from gotauth.plugins.two_factor import two_factor
from gotauth.social import github
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

SCOPES = ("projects:read", "projects:write")
env = os.environ


def github_from_env() -> list[OAuthProvider]:
    """GitHub when an OAuth app is configured; otherwise no GitHub button."""
    if not env.get("GITHUB_CLIENT_ID"):
        return []
    return [
        github(
            client_id=env["GITHUB_CLIENT_ID"], client_secret=env["GITHUB_CLIENT_SECRET"]
        )
    ]


def build_auth(
    database: Adapter | None = None,  # tests pass their own database, GitHub and mailer
    social_providers: Sequence[OAuthProvider] | None = None,
    email_sender: EmailSender | None = None,
) -> GotAuth:
    if database is None:
        url = env.get("DATABASE_URL", "sqlite+aiosqlite:///app.db")
        database = sqlalchemy_adapter(create_async_engine(url))
    base_url = env.get("BASE_URL", "http://localhost:3000")  # the Next.js origin
    return GotAuth(
        database=database,
        secret=env["GOTAUTH_SECRET"],
        base_url=base_url,
        email_password={"require_email_verification": True},
        social_providers=github_from_env()
        if social_providers is None
        else social_providers,
        email_sender=email_sender,  # None: printed to the console on localhost
        plugins=[
            api_key(allowed_scopes=SCOPES),
            two_factor(),
            passkey(),  # the relying party is the host of base_url: localhost
            organization(invitation_url=f"{base_url}/invitations/accept"),
        ],
    )


auth = build_auth()
