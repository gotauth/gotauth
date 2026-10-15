"""The example app against a real database, migrated with Alembic: a SQLite file,
and Postgres when GOTAUTH_TEST_POSTGRES_URL is set (the repository's dev container)."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
import pytest
from alembic import command
from alembic.config import Config

# Before the app is imported: app.main builds the default app from the environment.
os.environ.setdefault("GOTAUTH_SECRET", "test-" + "x" * 40)

from sqlalchemy.ext.asyncio import create_async_engine

from app.auth import build_auth
from app.main import create_app
from gotauth.contracts import ProviderUser
from gotauth.storage.sqlalchemy import sqlalchemy_adapter
from gotauth.testing import (
    CapturingMailer,
    StubOAuthProvider,
    fake_mailer,
    fresh_database_url,
)

BACKEND = Path(__file__).resolve().parent.parent
GITHUB_USER = ProviderUser(
    id="gh-42",
    email="ada@example.com",
    email_verified=True,
    name="Ada",
    image=None,
    raw={},
)


async def migrate(url: str, revision: str = "head") -> None:
    """`alembic upgrade head` (or to `revision`), as the app's container runs it."""
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    try:
        # migrations/env.py starts its own event loop, so Alembic gets a thread.
        config = Config(str(BACKEND / "alembic.ini"))
        await asyncio.to_thread(command.upgrade, config, revision)
    finally:
        if previous is None:
            del os.environ["DATABASE_URL"]
        else:
            os.environ["DATABASE_URL"] = previous


@pytest.fixture(params=["sqlite", "postgres"])
async def database_url(
    request: pytest.FixtureRequest, tmp_path: Path
) -> AsyncIterator[str]:
    """A migrated database: a SQLite file, or a fresh Postgres database."""
    if request.param == "sqlite":
        url = f"sqlite+aiosqlite:///{tmp_path / 'app.db'}"
        await migrate(url)
        yield url
        return
    base = os.environ.get("GOTAUTH_TEST_POSTGRES_URL")
    if not base:
        pytest.skip("GOTAUTH_TEST_POSTGRES_URL is not set")
    server = urlsplit(base)._replace(scheme="postgresql+asyncpg")
    async for url in fresh_database_url(urlunsplit(server)):  # dropped afterwards
        await migrate(url)
        yield url


@dataclass
class Example:
    """The app with GitHub replaced by a stub and email captured."""

    app: Any  # Any: the FastAPI app
    github: StubOAuthProvider
    mailer: CapturingMailer

    def browser(self) -> httpx.AsyncClient:
        """A browser on the Next.js origin (the proxy keeps one origin)."""
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://localhost:3000",
            headers={"origin": "http://localhost:3000"},
        )

    def curl(self) -> httpx.AsyncClient:
        """A script: no cookies kept, no Origin header."""
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://localhost:3000",
        )


@pytest.fixture
async def example(database_url: str) -> AsyncIterator[Example]:
    engine = create_async_engine(database_url)
    github = StubOAuthProvider("github", name="GitHub", users={"gh-code": GITHUB_USER})
    mailer = fake_mailer()
    auth = build_auth(
        database=sqlalchemy_adapter(engine),
        social_providers=[github],
        email_sender=mailer,
    )
    yield Example(app=create_app(auth), github=github, mailer=mailer)
    await auth.drain()
    await engine.dispose()
