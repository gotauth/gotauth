"""Sign up, sign in, API keys and sign out, as the htmx pages drive them."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from .conftest import Example

EMAIL = "ada@example.com"
PASSWORD = "correct horse battery"


async def signed_in(example: Example, http: httpx.AsyncClient) -> None:
    created = await http.post(
        "/api/auth/sign-up/email",
        json={"email": EMAIL, "password": PASSWORD, "callback_url": "/sign-in"},
    )
    assert created.json() == {"status": "verification_sent"}
    link = urlsplit(example.link("verify_email", EMAIL))
    verified = await http.get(f"{link.path}?{link.query}")
    assert verified.status_code in (302, 303)
    assert urlsplit(verified.headers["location"]).path == "/sign-in"
    response = await http.post(
        "/api/auth/sign-in/email", json={"email": EMAIL, "password": PASSWORD}
    )
    assert response.status_code == 200, response.text


async def test_pages_for_a_visitor(example: Example) -> None:
    async with example.browser() as browser:
        home = await browser.get("/")
        assert home.status_code == 200 and 'href="/sign-in"' in home.text
        assert "integrity=" in home.text  # the htmx script is pinned with SRI
        for page in ("/sign-in", "/sign-up"):
            assert (await browser.get(page)).status_code == 200
        assert (await browser.get("/static/app.js")).status_code == 200
        keys = await browser.get("/keys")
        assert keys.status_code in (302, 303)
        assert keys.headers["location"] == "/sign-in"
        assert (await browser.get("/keys/list")).status_code == 401


async def test_sign_in_keys_and_sign_out(example: Example) -> None:
    async with example.browser() as browser:
        await signed_in(example, browser)
        home = await browser.get("/")
        assert EMAIL in home.text and "Sign out" in home.text
        page = await browser.get("/keys")
        assert page.status_code == 200 and 'value="notes:read"' in page.text

        # What the create form sends: JSON, with scopes always a list.
        created = await browser.post(
            "/api/auth/api-keys", json={"name": "<b>ci</b>", "scopes": ["notes:read"]}
        )
        assert created.status_code == 200, created.text
        key, row = created.json()["key"], created.json()["api_key"]
        key_id = row["id"]
        table = (await browser.get("/keys/list")).text
        assert "&lt;b&gt;ci&lt;/b&gt;" in table and "<b>ci</b>" not in table
        assert f"{row['start']}..." in table and key not in table  # start only

        deleted = await browser.delete(f"/api/auth/api-keys/{key_id}")
        assert deleted.status_code == 200
        assert "No API keys yet." in (await browser.get("/keys/list")).text

        signed_out = await browser.post("/api/auth/sign-out")
        assert signed_out.status_code == 200
        assert 'href="/sign-in"' in (await browser.get("/")).text


async def test_changes_need_json_and_this_origin(example: Example) -> None:
    async with example.browser() as browser:
        await signed_in(example, browser)
        # A plain HTML form post (what a cross-site form can send) is refused.
        form = await browser.post("/api/auth/api-keys", data={"name": "x"})
        assert form.status_code == 415
        # So is a JSON request from another origin with the session cookie.
        foreign = await browser.post(
            "/api/auth/api-keys",
            json={"name": "x", "scopes": []},
            headers={"origin": "https://evil.example.com"},
        )
        assert foreign.status_code == 403
        assert foreign.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"
