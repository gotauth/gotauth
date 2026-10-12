"""All of this app's auth configuration."""

from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import create_async_engine

from gotauth import GotAuth
from gotauth.contracts import Adapter, EmailSender
from gotauth.plugins.api_key import api_key
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

SCOPES = ("notes:read", "notes:write")
env = os.environ


def build_auth(
    database: Adapter | None = None,  # tests pass their own database and mailer
    email_sender: EmailSender | None = None,
) -> GotAuth:
    engine = create_async_engine(env.get("DATABASE_URL", "sqlite+aiosqlite:///app.db"))
    return GotAuth(
        database=database or sqlalchemy_adapter(engine),
        secret=env["GOTAUTH_SECRET"],
        base_url=env.get("BASE_URL", "http://localhost:8000"),
        email_password={"require_email_verification": True},
        email_sender=email_sender,  # None: printed to the console on localhost
        plugins=[api_key(allowed_scopes=SCOPES)],
    )


auth = build_auth()
