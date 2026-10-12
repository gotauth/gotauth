"""The Litestar example on a SQLite file, with emails captured."""

from __future__ import annotations

import os
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

# Before the app is imported: app.main builds the default app from the environment.
os.environ.setdefault("GOTAUTH_SECRET", "test-" + "x" * 40)

from sqlalchemy.ext.asyncio import create_async_engine

from app.auth import build_auth
from app.main import create_app
from gotauth.contracts import EmailKind
from gotauth.storage.sqlalchemy import create_missing, sqlalchemy_adapter
from gotauth.testing import CapturingMailer, fake_mailer

ORIGIN = "http://localhost:8000"


@dataclass
class Example:
    app: Any  # Any: the Litestar app
    mailer: CapturingMailer

    def browser(self) -> httpx.AsyncClient:
        """A browser: keeps cookies and sends Origin, as htmx requests do."""
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url=ORIGIN,
            headers={"origin": ORIGIN},
        )

    def link(self, kind: EmailKind, to: str) -> str:
        """The link in the newest email of a kind, as the console prints it."""
        match = re.search(r"https?://\S+", self.mailer.last(kind, to).text)
        assert match
        return match.group(0)


@pytest.fixture
async def example(tmp_path: Path) -> AsyncIterator[Example]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'app.db'}")
    mailer = fake_mailer()
    auth = build_auth(database=sqlalchemy_adapter(engine), email_sender=mailer)
    await create_missing(engine, auth.schema)  # what `gotauth migrate` does
    yield Example(app=create_app(auth), mailer=mailer)
    await auth.drain()
    await engine.dispose()
