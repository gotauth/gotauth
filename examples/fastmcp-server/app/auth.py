"""All of this app's auth configuration."""

from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import create_async_engine

from gotauth import GotAuth
from gotauth.contracts import Adapter, EmailSender
from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

env = os.environ

BASE_URL = env.get("BASE_URL", "http://localhost:8000").rstrip("/")
"""The public origin: a tunnel URL when a hosted client such as Claude connects."""
MCP_URL = f"{BASE_URL}/mcp"
"""The MCP server's URL, which access tokens must name as their audience."""
SCOPES = ("projects:read", "projects:write")
INSPECTOR_ORIGIN = "http://localhost:6274"
INSPECTOR_REDIRECT = f"{INSPECTOR_ORIGIN}/oauth/callback"
"""MCP Inspector's OAuth callback; the app seeds a public client for it."""


def build_auth(
    database: Adapter | None = None,  # tests pass their own database and mailer
    email_sender: EmailSender | None = None,
) -> GotAuth:
    if database is None:
        url = env.get("DATABASE_URL", "sqlite+aiosqlite:///app.db")
        database = sqlalchemy_adapter(create_async_engine(url))
    return GotAuth(
        database=database,
        secret=env["GOTAUTH_SECRET"],
        base_url=BASE_URL,
        # A demo: sign up and connect at once. Turn this on in a real app.
        email_password={"require_email_verification": False},
        email_sender=email_sender,  # None: printed to the console on localhost
        plugins=[
            oauth_provider(
                mcp=True,
                resources=[MCP_URL],
                scopes=("openid", "profile", "email", *SCOPES, "offline_access"),
                login_page="/sign-in",
                # Claude and other hosted clients register themselves (RFC 7591).
                allow_dynamic_registration=True,
            )
        ],
    )


auth = build_auth()
