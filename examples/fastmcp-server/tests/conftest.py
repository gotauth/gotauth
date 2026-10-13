"""The fastmcp-server example on a SQLite file, with its lifespan running."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

# Before the app is imported: app.main builds the default app from the environment.
os.environ.setdefault("GOTAUTH_SECRET", "test-" + "x" * 40)
os.environ["BASE_URL"] = "http://localhost:8000"  # not a tunnel URL from .env

from sqlalchemy.ext.asyncio import create_async_engine

from app.auth import build_auth
from app.main import create_app
from gotauth.storage.sqlalchemy import create_missing, sqlalchemy_adapter
from gotauth.testing import fake_mailer

ORIGIN = "http://localhost:8000"


@dataclass
class Example:
    app: Any  # Any: the FastAPI app
    auth: Any  # Any: GotAuth

    def browser(self) -> httpx.AsyncClient:
        """A browser: keeps cookies and sends Origin, as the page's script does."""
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url=ORIGIN,
            headers={"origin": ORIGIN},
        )

    @asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        """The app's lifespan (the MCP session manager), entered and left in the
        test's own task, as anyio requires."""
        async with self.app.router.lifespan_context(self.app):
            yield

    def mcp_client(self) -> httpx.AsyncClient:
        """An MCP client: no cookies, only the bearer token it is given."""
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url=ORIGIN
        )


@pytest.fixture
async def example(tmp_path: Path) -> AsyncIterator[Example]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'app.db'}")
    auth = build_auth(database=sqlalchemy_adapter(engine), email_sender=fake_mailer())
    await create_missing(engine, auth.schema)  # what `gotauth migrate` does
    yield Example(app=create_app(auth), auth=auth)
    await engine.dispose()
