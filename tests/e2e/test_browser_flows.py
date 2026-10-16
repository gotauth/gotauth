"""Real-browser flows on examples/fastapi-nextjs (work package Q2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
from playwright.sync_api import Browser, Page, expect

from gotauth.crypto import totp

from .conftest import (
    APP,
    PASSWORD,
    emailed_link,
    expect_home,
    new_email,
    sign_in,
    sign_out,
    sign_up_and_verify,
)


def test_sign_up_verify_sign_in_and_out(page: Page) -> None:
    email = new_email("ada")
    sign_up_and_verify(page, email)
    expect_home(page, email)
    sign_out(page)
    # Signed out: the projects API refuses the browser.
    assert page.request.get("/api/projects").status == 401


def test_two_factor_setup_and_sign_in(page: Page, user: str) -> None:
    page.goto("/security")
    page.get_by_label("Password").fill(PASSWORD)
    page.get_by_role("button", name="Set up").click()
    secret = page.get_by_test_id("totp-secret").inner_text()
    expect(page.get_by_test_id("backup-codes")).to_be_visible()
    now = datetime.now(UTC)
    page.get_by_label("I saved my backup codes").check()
    page.get_by_label("3. Enter the code from the app").fill(totp(secret, at=now))
    page.get_by_role("button", name="Turn on").click()
    expect(page.get_by_role("button", name="Turn off two-factor")).to_be_visible()

    sign_out(page)
    sign_in(page, user)
    # The password alone is not enough: the form asks for a code.
    code_field = page.get_by_label("Code from your authenticator app")
    expect(code_field).to_be_visible()
    # The step that confirmed setup works once; the next one is accepted.
    code_field.fill(totp(secret, at=now + timedelta(seconds=30)))
    page.get_by_role("button", name="Continue").click()
    expect_home(page, user)


def test_passkey_register_and_usernameless_sign_in(page: Page, user: str) -> None:
    # A virtual authenticator in Chromium: the "fingerprint" always says yes.
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }
        },
    )
    page.goto("/security")
    page.get_by_label("Name for a new passkey").fill("E2E laptop")
    page.get_by_role("button", name="Add a passkey").click()
    expect(page.get_by_test_id("passkeys")).to_contain_text("E2E laptop")

    sign_out(page)
    page.goto("/sign-in")
    page.get_by_role("button", name="Sign in with a passkey").click()
    expect_home(page, user)


def test_api_key_works_then_revoked(page: Page, user: str) -> None:
    page.goto("/keys")
    page.get_by_role("button", name="Create key").click()
    page.get_by_label("Name", exact=True).fill("e2e")
    page.get_by_label("projects:read").check()
    page.get_by_role("dialog").get_by_role("button", name="Create key").click()
    key = page.get_by_test_id("new-api-key").inner_text()
    assert key.startswith("gak_")
    page.get_by_role("button", name="Done").click()

    # A script with the key, no browser.
    ok = httpx.get(f"{APP}/api/v1/projects", headers={"x-api-key": key})
    assert ok.status_code == 200, ok.text

    page.get_by_role("button", name="Delete key e2e").click()
    expect(page.get_by_role("button", name="Delete key e2e")).to_have_count(0)
    denied = httpx.get(f"{APP}/api/v1/projects", headers={"x-api-key": key})
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "API_KEY_INVALID"


def test_organization_invitation(browser: Browser, page: Page, user: str) -> None:
    org = f"Acme {user[5:11]}"
    page.goto("/organizations")
    page.get_by_label("Name", exact=True).fill(org)
    page.get_by_role("button", name="Create organization").click()
    expect(page.get_by_test_id("active-organization")).to_contain_text(org)

    invitee = new_email("bob")
    page.get_by_label("Email").fill(invitee)
    page.get_by_role("button", name="Send invitation").click()
    expect(page.get_by_test_id("invitations")).to_contain_text(invitee)
    link = emailed_link(invitee, "/invitations/accept")

    # The invitee, in another browser, signs up and opens the emailed link.
    with browser.new_context(base_url=APP) as context:
        bob = context.new_page()
        sign_up_and_verify(bob, invitee)
        expect_home(bob, invitee)
        bob.goto(link)
        bob.get_by_role("button", name="Join").click()
        expect(bob.get_by_test_id("active-organization")).to_contain_text(org)
        expect(bob.get_by_test_id("members")).to_contain_text(invitee)
