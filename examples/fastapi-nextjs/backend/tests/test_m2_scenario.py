"""The M2 scenario from docs/plan/README.md, step by step, as the README walks it."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from gotauth.contracts import EmailKind

from .conftest import Example

EMAIL = "ada@example.com"
PASSWORD = "correct horse battery"


def emailed_link(example: Example, kind: EmailKind) -> str:
    """The link in the newest email of a kind, as the console prints it."""
    text = example.mailer.last(kind, EMAIL).text
    match = re.search(r"https?://\S+", text)
    assert match, text
    return match.group(0)


async def test_m2_scenario(example: Example) -> None:
    # 1. Sign up. The answer never says whether the email was new (no enumeration).
    async with example.browser() as browser:
        signed_up = await browser.post(
            "/api/auth/sign-up/email",
            json={"email": EMAIL, "password": PASSWORD, "callback_url": "/sign-in"},
        )
        assert signed_up.status_code == 200, signed_up.text
        assert signed_up.json() == {"status": "verification_sent"}

        # 2. Verify the email with the link from the console (here: the fake mailer).
        link = urlsplit(emailed_link(example, "verify_email"))
        assert (link.scheme, link.netloc) == ("http", "localhost:3000")
        assert link.path == "/api/auth/verify-email"
        verified = await browser.get(f"{link.path}?{link.query}")
        assert verified.status_code in (302, 303), verified.text
        assert urlsplit(verified.headers["location"]).path == "/sign-in"

    # 3. Log in with GitHub in a fresh browser: the verified GitHub email links to the
    # account. 4. The session cookie is set.
    async with example.browser() as browser:
        config = (await browser.get("/api/config")).json()
        assert config == {
            "social_providers": [{"id": "github", "name": "GitHub"}],
            "api_key_scopes": ["projects:read", "projects:write"],
        }
        started = await browser.post(
            "/api/auth/sign-in/social", json={"provider": "github", "callback_url": "/"}
        )
        assert started.status_code == 200, started.text
        callback = example.github.approve(started.json()["url"], "gh-code")
        landed = await browser.get("/api/auth/callback/github", params=callback)
        assert landed.status_code in (302, 303), landed.text
        assert urlsplit(landed.headers["location"]).path == "/"
        assert browser.cookies.get("gotauth.session_token")
        session = (await browser.get("/api/auth/session")).json()
        assert session["user"]["email"] == EMAIL
        mine = await browser.get("/api/projects")
        assert mine.status_code == 200 and len(mine.json()) == 3

        # 5. Create an API key. The raw key is in this answer only.
        created = await browser.post(
            "/api/auth/api-keys", json={"name": "laptop", "scopes": ["projects:read"]}
        )
        assert created.status_code == 200, created.text
        key, key_id = created.json()["key"], created.json()["api_key"]["id"]
        assert key.startswith("gak_")
        listed = (await browser.get("/api/auth/api-keys")).json()
        assert key not in str(listed)

        # 6. curl a protected route with the key: 200.
        async with example.curl() as curl:
            ok = await curl.get("/api/v1/projects", headers={"x-api-key": key})
            assert ok.status_code == 200, ok.text
            assert ok.json() == mine.json()

        # 7. Revoke the key: the next call gets a 401.
        revoked = await browser.delete(f"/api/auth/api-keys/{key_id}")
        assert revoked.status_code == 200, revoked.text
        async with example.curl() as curl:
            denied = await curl.get("/api/v1/projects", headers={"x-api-key": key})
        assert denied.status_code == 401
        assert denied.json()["error"]["code"] == "API_KEY_INVALID"  # P1's code
        assert denied.headers["www-authenticate"].startswith("Bearer")


async def test_project_routes_keep_their_credentials_apart(example: Example) -> None:
    async with example.browser() as browser:
        await browser.post(
            "/api/auth/sign-up/email", json={"email": EMAIL, "password": PASSWORD}
        )
        link = urlsplit(emailed_link(example, "verify_email"))
        token = parse_qs(link.query)["token"][0]
        await browser.get("/api/auth/verify-email", params={"token": token})
        signed_in = await browser.post(
            "/api/auth/sign-in/email", json={"email": EMAIL, "password": PASSWORD}
        )
        assert signed_in.status_code == 200, signed_in.text
        # The key route takes keys only, even from a signed-in browser.
        assert (await browser.get("/api/v1/projects")).status_code == 401
        write_only = await browser.post(
            "/api/auth/api-keys", json={"name": "ci", "scopes": ["projects:write"]}
        )
        key = write_only.json()["key"]
    async with example.curl() as curl:
        # A key without projects:read is refused with the scope it lacks.
        refused = await curl.get("/api/v1/projects", headers={"x-api-key": key})
        assert refused.status_code == 403
        assert refused.json()["error"]["details"]["required"] == ["projects:read"]
        # The browser route takes sessions only.
        assert (
            await curl.get("/api/projects", headers={"x-api-key": key})
        ).status_code == 401
