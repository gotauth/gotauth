"""Origin and CSRF checks, content types, open redirects, session fixation and cookie
flags (CONTRACTS 7, 10.1)."""

from __future__ import annotations

import httpx
import pytest

from .conftest import PASSWORD, full_app


async def signed_in(app: object) -> tuple[httpx.AsyncClient, httpx.Cookies]:
    http = app.client()  # type: ignore[attr-defined]
    await app.verified_user(http)  # type: ignore[attr-defined]
    return http, http.cookies


@pytest.mark.parametrize(
    ("headers", "allowed"),
    [
        ({}, False),
        ({"origin": "https://evil.example.com"}, False),
        ({"origin": "null"}, False),
        ({"referer": "https://evil.example.com/page"}, False),
        ({"referer": "http://localhost:8000/settings"}, True),
        ({"origin": "http://localhost:8000"}, True),
    ],
)
async def test_cookie_posts_need_a_trusted_origin(
    headers: dict[str, str], allowed: bool
) -> None:
    app = full_app()
    http, cookies = await signed_in(app)
    async with app.client(origin=False) as bare:
        bare.cookies = cookies
        response = await bare.post("/sessions/revoke-others", headers=headers)
    await http.aclose()
    if allowed:
        assert response.status_code == 200
    else:
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"


async def test_bearer_requests_are_exempt_from_origin_checks() -> None:
    app = full_app(sessions={"expose_token": True})
    async with app.client() as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        await http.get(
            "/verify-email", params={"token": app.last_token("verify_email")}
        )
        token = (
            await http.post(
                "/sign-in/email",
                json={"email": "ada@example.com", "password": PASSWORD},
            )
        ).json()["token"]
    async with app.client(origin=False) as bare:
        response = await bare.post(
            "/sessions/revoke-others", headers={"authorization": f"Bearer {token}"}
        )
    assert response.status_code == 200


async def test_form_posts_to_json_endpoints_are_refused() -> None:
    app = full_app()
    async with app.client() as http:
        response = await http.post(
            "/sign-in/email", data={"email": "a@example.com", "password": "x" * 10}
        )
    assert response.status_code == 415


async def test_oauth_consent_needs_a_trusted_origin() -> None:
    app = full_app()
    http, cookies = await signed_in(app)
    async with app.client(origin=False) as bare:
        bare.cookies = cookies
        response = await bare.post(
            "/oauth2/consent", data={"consent_id": "x", "accept": "true"}
        )
    await http.aclose()
    assert response.status_code == 403


@pytest.mark.parametrize(
    "target",
    [
        "//evil.example.com/x",
        "/\\evil.example.com",
        "https:evil.example.com",
        "javascript:alert(1)",
        "http://user@localhost:8000/x",
        "https://evil.example.com/x",
        "http://evil.example.com/x",
        " /x",
    ],
)
async def test_open_redirects_are_refused(target: str) -> None:
    app = full_app(trusted_origins=["https://*.example.com"])
    async with app.client() as http:
        response = await http.post(
            "/request-password-reset",
            json={"email": "a@example.com", "redirect_to": target},
        )
    if target == "https://evil.example.com/x":
        # Allowed by the wildcard on purpose; anything outside it is refused.
        assert response.status_code == 200
    else:
        assert response.status_code == 400, target
        assert response.json()["error"]["code"] == "INVALID_REQUEST"


async def test_wildcard_does_not_match_the_bare_domain_or_lookalikes() -> None:
    app = full_app(trusted_origins=["https://*.example.com"])
    async with app.client() as http:
        for target in ("https://example.com.evil.test/x", "https://evilexample.com/x"):
            response = await http.post(
                "/request-password-reset",
                json={"email": "a@example.com", "redirect_to": target},
            )
            assert response.status_code == 400, target


async def test_a_planted_session_cookie_is_never_adopted() -> None:
    app = full_app()
    planted = "gas_" + "A" * 43
    async with app.client() as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        await http.get(
            "/verify-email", params={"token": app.last_token("verify_email")}
        )
        http.cookies.set("gotauth.session_token", planted)
        response = await http.post(
            "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        issued = response.cookies.get("gotauth.session_token")
    assert issued and issued != planted
    async with app.client() as other:
        other.cookies.set("gotauth.session_token", planted)
        assert (await other.get("/session")).json() is None


async def test_cookie_flags_on_https() -> None:
    app = full_app(base_url="https://auth.example.com")
    async with app.client() as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        await app.auth.drain()
        await http.get(
            "/verify-email", params={"token": app.last_token("verify_email")}
        )
        response = await http.post(
            "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("__Secure-gotauth.session_token=")
    for flag in ("HttpOnly", "Secure", "SameSite=Lax", "Path=/"):
        assert flag in cookie, flag


@pytest.mark.skip(reason="P2 (finish_challenge after a second factor) has not merged")
async def test_second_factor_completion_issues_a_new_token() -> None:
    raise AssertionError("covered once P2 merges")
