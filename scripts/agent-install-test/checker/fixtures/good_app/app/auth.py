"""A correct GotAuth setup, as the skill describes it (seeded for the checker's tests)."""

import os

from sqlalchemy.ext.asyncio import create_async_engine

from gotauth import GotAuth
from gotauth.plugins.api_key import api_key
from gotauth.social import github
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

auth = GotAuth(
    database=sqlalchemy_adapter(
        create_async_engine(
            os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///app.db")
        )
    ),
    secret=os.environ["GOTAUTH_SECRET"],
    base_url=os.environ.get("BASE_URL", "http://localhost:8000"),
    social_providers=[
        github(
            client_id=os.environ["GITHUB_CLIENT_ID"],
            client_secret=os.environ["GITHUB_CLIENT_SECRET"],
        )
    ],
    plugins=[api_key(allowed_scopes=["projects:read"])],
)
