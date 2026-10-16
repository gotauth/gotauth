"""Fixtures for the end-to-end tests (work package Q2).

The app runs in other containers (tests/e2e/compose.yaml); these fixtures wait for it,
read the emails the backend prints, and drive the pages the way a person would.
Nothing here sleeps for a fixed time: every wait is on a page state or a condition.
"""

from __future__ import annotations

import os
import re
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import Page, expect

APP = os.environ.get("E2E_APP_URL", "http://localhost:3000")
BACKEND_LOG = Path(os.environ.get("E2E_BACKEND_LOG", "/logs/backend.log"))
PASSWORD = "correct horse battery staple"

# The console email sender's format (gotauth.email.ConsoleSender).
_EMAIL = re.compile(
    r"gotauth email to (?P<to>\S+)\nSubject: (?P<subject>[^\n]*)\n\n"
    r"(?P<body>.*?)\n-{60}",
    re.DOTALL,
)


def wait_for(condition: Callable[[], object], what: str, timeout: float = 30) -> object:
    """Poll ``condition`` until it returns something truthy."""
    deadline = time.monotonic() + timeout
    while True:
        value = condition()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.2)


@pytest.fixture(scope="session", autouse=True)
def app_is_up() -> None:
    """Wait until the frontend answers and proxies to the backend."""

    def ready() -> bool:
        try:
            return httpx.get(f"{APP}/api/config", timeout=5).status_code == 200
        except httpx.HTTPError:
            return False

    wait_for(ready, "the example app", timeout=180)


@pytest.fixture(scope="session")
def base_url() -> str:
    """pytest-playwright: page.goto("/x") opens the app."""
    return APP


def emailed_link(to: str, contains: str) -> str:
    """The link in the newest email to ``to`` that contains ``contains``."""

    def find() -> str | None:
        if not BACKEND_LOG.exists():
            return None
        text = BACKEND_LOG.read_text(encoding="utf-8", errors="replace")
        for message in reversed(list(_EMAIL.finditer(text))):
            if message.group("to") != to:
                continue
            for url in re.findall(r"https?://\S+", message.group("body")):
                if contains in url:
                    return url
        return None

    return str(wait_for(find, f"an email to {to} with {contains!r}"))


def new_email(name: str = "user") -> str:
    """A fresh address per test: every run shares one database."""
    return f"{name}-{uuid.uuid4().hex[:10]}@example.com"


def sign_up_and_verify(page: Page, email: str) -> None:
    """Sign up in the browser, open the verification link, and sign in."""
    page.goto("/sign-up")
    page.get_by_label("Email", exact=True).fill(email)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Create account").click()
    expect(page.get_by_text("Check your email")).to_be_visible()
    page.goto(emailed_link(email, "/api/auth/verify-email"))
    sign_in(page, email)


def sign_in(page: Page, email: str) -> None:
    page.goto("/sign-in")
    page.get_by_label("Email", exact=True).fill(email)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Sign in", exact=True).click()


def expect_home(page: Page, email: str) -> None:
    expect(page.get_by_text(f"Signed in as {email}")).to_be_visible()
    expect(page.get_by_test_id("projects")).to_be_visible()


def sign_out(page: Page) -> None:
    page.get_by_role("button", name="Account menu").click()
    page.get_by_role("menuitem", name="Sign out").click()
    expect(
        page.get_by_role("banner").get_by_role("link", name="Sign in")
    ).to_be_visible()


@pytest.fixture
def user(page: Page) -> Iterator[str]:
    """A signed-up, verified and signed-in user; yields the email."""
    email = new_email()
    sign_up_and_verify(page, email)
    expect_home(page, email)
    yield email
