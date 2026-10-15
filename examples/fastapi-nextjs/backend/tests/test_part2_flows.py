"""The flows part 2 adds to the example: two-factor, passkeys and organizations, as
the frontend pages drive them (and Q2's browser tests after them)."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from gotauth.crypto import totp
from gotauth.plugins.passkey.testing import SoftAuthenticator

from .conftest import Example, migrate

PASSWORD = "correct horse battery"
ORIGIN = "http://localhost:3000"


async def signed_in(example: Example, browser: httpx.AsyncClient, email: str) -> None:
    """Sign up, verify the email from the console, and sign in."""
    signed_up = await browser.post(
        "/api/auth/sign-up/email", json={"email": email, "password": PASSWORD}
    )
    assert signed_up.status_code == 200, signed_up.text
    link = re.search(r"https?://\S+", example.mailer.last("verify_email", email).text)
    assert link
    token = parse_qs(urlsplit(link.group(0)).query)["token"][0]
    await browser.get("/api/auth/verify-email", params={"token": token})
    answer = await browser.post(
        "/api/auth/sign-in/email", json={"email": email, "password": PASSWORD}
    )
    assert answer.status_code == 200, answer.text
    assert "session" in answer.json()


async def test_two_factor_setup_and_sign_in(example: Example) -> None:
    email = "ada@example.com"
    async with example.browser() as browser:
        await signed_in(example, browser, email)
        started = await browser.post(
            "/api/auth/two-factor/enable", json={"password": PASSWORD}
        )
        assert started.status_code == 200, started.text
        secret = parse_qs(urlsplit(started.json()["totp_uri"]).query)["secret"][0]
        backup_codes = started.json()["backup_codes"]
        now = datetime.now(UTC)
        confirmed = await browser.post(
            "/api/auth/two-factor/verify-totp", json={"code": totp(secret, at=now)}
        )
        assert confirmed.json() == {"status": "enabled"}
        session = (await browser.get("/api/auth/session")).json()
        assert session["user"]["two_factor_enabled"] is True

    # A new browser: the password alone gets a challenge, not a session.
    async with example.browser() as browser:
        first = await browser.post(
            "/api/auth/sign-in/email", json={"email": email, "password": PASSWORD}
        )
        assert first.json()["challenge"]["type"] == "two_factor"
        assert not browser.cookies.get("gotauth.session_token")
        # The next time step: the one used to confirm setup works only once.
        later = now + timedelta(seconds=30)
        answered = await browser.post(
            "/api/auth/two-factor/verify-totp",
            json={"code": totp(secret, at=later), "trust_device": True},
        )
        assert answered.status_code == 200, answered.text
        assert (await browser.get("/api/projects")).status_code == 200

    # A backup code works once.
    async with example.browser() as browser:
        await browser.post(
            "/api/auth/sign-in/email", json={"email": email, "password": PASSWORD}
        )
        used = await browser.post(
            "/api/auth/two-factor/verify-backup-code", json={"code": backup_codes[0]}
        )
        assert used.status_code == 200, used.text
    async with example.browser() as browser:
        await browser.post(
            "/api/auth/sign-in/email", json={"email": email, "password": PASSWORD}
        )
        again = await browser.post(
            "/api/auth/two-factor/verify-backup-code", json={"code": backup_codes[0]}
        )
        assert again.json()["error"]["code"] == "TWO_FACTOR_INVALID_CODE"


async def test_passkey_register_and_usernameless_sign_in(example: Example) -> None:
    device = SoftAuthenticator(origin=ORIGIN)
    async with example.browser() as browser:
        await signed_in(example, browser, "ada@example.com")
        options = await browser.post("/api/auth/passkey/register/options")
        assert options.status_code == 200, options.text
        assert options.json()["rp"]["id"] == "localhost"
        registered = await browser.post(
            "/api/auth/passkey/register/verify",
            json={"response": device.create(options.json()), "name": "Laptop"},
        )
        assert registered.status_code == 200, registered.text
        assert registered.json()["name"] == "Laptop"

    async with example.browser() as browser:
        options = await browser.post("/api/auth/passkey/sign-in/options")
        signed = await browser.post(
            "/api/auth/passkey/sign-in/verify",
            json={"response": device.get(options.json())},
        )
        assert signed.status_code == 200, signed.text
        assert signed.json()["user"]["email"] == "ada@example.com"
        assert (await browser.get("/api/projects")).status_code == 200


async def test_organization_invitation_by_email(example: Example) -> None:
    async with example.browser() as ada:
        await signed_in(example, ada, "ada@example.com")
        created = await ada.post(
            "/api/auth/organization/create", json={"name": "Acme", "slug": "acme"}
        )
        assert created.status_code == 200, created.text
        org_id = created.json()["id"]
        invited = await ada.post(
            "/api/auth/organization/invite-member",
            json={"email": "bob@example.com", "organization_id": org_id},
        )
        assert invited.status_code == 200, invited.text

    # The emailed link opens the frontend's accept page.
    text_body = example.mailer.last("invitation", "bob@example.com").text
    link = re.search(r"https?://\S+", text_body)
    assert link
    url = urlsplit(link.group(0))
    assert (url.netloc, url.path) == ("localhost:3000", "/invitations/accept")
    query = parse_qs(url.query)

    async with example.browser() as bob:
        await signed_in(example, bob, "bob@example.com")
        accepted = await bob.post(
            "/api/auth/organization/accept-invitation",
            json={
                "invitation_id": query["invitation_id"][0],
                "token": query["token"][0],
            },
        )
        assert accepted.status_code == 200, accepted.text
        await bob.post(
            "/api/auth/organization/set-active", json={"organization_id": org_id}
        )
        session = (await bob.get("/api/auth/session")).json()
        assert session["session"]["active_organization_id"] == org_id
        orgs = (await bob.get("/api/auth/organization/list")).json()
        assert [(o["name"], o["role"]) for o in orgs["organizations"]] == [
            ("Acme", "member")
        ]


async def test_upgrade_keeps_users_from_part_one(
    tmp_path: Path,
) -> None:
    # Part 2's revision adds user.two_factor_enabled to a table that has rows.
    url = f"sqlite+aiosqlite:///{tmp_path}/old.db"
    await migrate(url, "ea341253f243")
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO auth_user (id, email, email_verified, created_at, "
                    "updated_at) VALUES ('usr_1', 'old@example.com', 1, "
                    "'2026-10-01 00:00:00', '2026-10-01 00:00:00')"
                )
            )
        await migrate(url)
        async with engine.connect() as conn:
            row = (
                await conn.execute(text("SELECT two_factor_enabled FROM auth_user"))
            ).one()
        assert row[0] in (False, 0)
    finally:
        await engine.dispose()
