"""Rate limits (CONTRACTS 10.2) and replay of single-use secrets."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from gotauth.crypto import totp
from gotauth.plugins.passkey.testing import SoftAuthenticator
from gotauth.testing import TEST_BASE_URL

from .conftest import PASSWORD, App, full_app, oauth_client, oauth_code, oauth_tokens

XFF = {"ip_headers": ("x-forwarded-for",)}


async def statuses_with_rotating_xff(
    app: App, path: str, body: dict[str, str]
) -> list[int]:
    """Send 11 requests, each with a different X-Forwarded-For address."""
    async with app.client() as http:
        return [
            (
                await http.post(
                    path, json=body, headers={"x-forwarded-for": f"198.51.100.{i + 1}"}
                )
            ).status_code
            for i in range(11)
        ]


async def test_sign_in_limit_with_retry_after() -> None:
    app = full_app()
    async with app.client() as http:
        responses = [
            await http.post(
                "/sign-in/email",
                json={"email": f"user{i}@example.com", "password": "wrong password"},
            )
            for i in range(6)
        ]
    assert [r.status_code for r in responses] == [401] * 5 + [429]
    limited = responses[-1]
    assert int(limited.headers["retry-after"]) > 0
    assert limited.json()["error"]["code"] == "RATE_LIMITED"


async def test_forwarded_ips_count_only_from_trusted_proxies() -> None:
    # The header is configured but the peer (127.0.0.1) is not a trusted proxy, so
    # rotating the header must not spread the requests over several IPs.
    path = "/request-password-reset"
    untrusted = full_app(advanced=XFF)
    statuses = await statuses_with_rotating_xff(
        untrusted, path, {"email": "x@example.com", "redirect_to": "/reset"}
    )
    assert statuses[:5] == [200] * 5 and statuses[5] == 429
    # Control: once the peer is trusted, each address gets its own window.
    trusted = full_app(advanced={**XFF, "trusted_proxies": ("127.0.0.1",)})
    statuses = await statuses_with_rotating_xff(
        trusted, path, {"email": "x@example.com", "redirect_to": "/reset"}
    )
    assert statuses[:10] == [200] * 10


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/sign-in/email", {"password": "wrong password"}),
        ("/request-password-reset", {"redirect_to": "/reset"}),
        ("/magic-link/send", {}),
        ("/email-otp/send", {"type": "sign_in"}),
    ],
)
async def test_per_email_limits_hold_across_rotating_ips(
    path: str, body: dict[str, str]
) -> None:
    # Distinct client IPs as GotAuth resolves them, through a trusted proxy.
    app = full_app(advanced={**XFF, "trusted_proxies": ("127.0.0.1",)})
    statuses = await statuses_with_rotating_xff(
        app, path, {"email": "ada@example.com", **body}
    )
    assert 429 not in statuses[:10]
    assert statuses[10] == 429


async def test_verification_and_reset_tokens_work_once() -> None:
    app = full_app()
    async with app.client() as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        verify = app.last_token("verify_email")
        first = await http.get("/verify-email", params={"token": verify})
        assert first.status_code == 200
        replay = await http.get("/verify-email", params={"token": verify})
        assert replay.status_code == 400
        assert replay.json()["error"]["code"] == "TOKEN_INVALID"
        await http.post(
            "/request-password-reset",
            json={"email": "ada@example.com", "redirect_to": "/reset"},
        )
        body = {
            "token": app.last_token("reset_password"),
            "new_password": "another one",
        }
        assert (await http.post("/reset-password", json=body)).status_code == 200
        replay = await http.post("/reset-password", json=body)
        assert replay.json()["error"]["code"] == "TOKEN_INVALID"


async def test_a_replayed_code_revokes_what_it_produced() -> None:
    app = full_app()
    async with app.client() as http:
        await app.verified_user(http)
        client_id, _ = await oauth_client(app)
        code, verifier = await oauth_code(http, client_id)
        tokens = (await oauth_tokens(http, client_id, code, verifier)).json()
        replay = await oauth_tokens(http, client_id, code, verifier)
    assert replay.json()["error"] == "invalid_grant"
    result = await app.auth.api.call(
        "verify_access_token", body={"token": tokens["access_token"]}
    )
    assert not result.valid


async def test_a_replayed_refresh_token_revokes_the_family() -> None:
    app = full_app()
    async with app.client() as http:
        await app.verified_user(http)
        client_id, _ = await oauth_client(app)
        code, verifier = await oauth_code(http, client_id)
        first = (await oauth_tokens(http, client_id, code, verifier)).json()

        async def refresh(token: str) -> dict[str, str]:
            form = {
                "grant_type": "refresh_token",
                "refresh_token": token,
                "client_id": client_id,
            }
            return (await http.post("/oauth2/token", data=form)).json()

        second = await refresh(first["refresh_token"])
        assert "access_token" in second
        assert (await refresh(first["refresh_token"]))["error"] == "invalid_grant"
        # The stolen-token reuse revoked the whole family, including the rotation.
        assert (await refresh(second["refresh_token"]))["error"] == "invalid_grant"
    result = await app.auth.api.call(
        "verify_access_token", body={"token": second["access_token"]}
    )
    assert not result.valid


# Replay of the plugins' one-time secrets. Rate limits are off: these tests are
# about what a second use gets, not about how many tries an address has.


async def two_factor_on(app: App, http: httpx.AsyncClient) -> tuple[str, list[str]]:
    """Turn two-factor on for the signed-in user: ``(secret, backup codes)``."""
    started = (
        await http.post("/two-factor/enable", json={"password": PASSWORD})
    ).json()
    secret = parse_qs(urlsplit(started["totp_uri"]).query)["secret"][0]
    code = totp(secret, at=app.clock.now())
    confirmed = await http.post("/two-factor/verify-totp", json={"code": code})
    assert confirmed.status_code == 200, confirmed.text
    app.clock.advance("30s")  # the next code is a new time step
    return secret, list(started["backup_codes"])


async def challenged(*browsers: httpx.AsyncClient) -> None:
    """Sign in with the password in each browser, which gets the 2FA challenge."""
    for http in browsers:
        started = await http.post(
            "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        assert started.json()["challenge"]["type"] == "two_factor", started.text


async def test_a_totp_code_and_a_backup_code_work_once() -> None:
    app = full_app(rate_limit={"enabled": False})
    async with app.client() as http:
        await app.verified_user(http)
        secret, backup = await two_factor_on(app, http)
    code = totp(secret, at=app.clock.now())
    async with app.client() as first, app.client() as second:
        await challenged(first, second)
        used = await first.post("/two-factor/verify-totp", json={"code": code})
        assert used.status_code == 200, used.text
        # The same code in another browser, inside its 30 seconds.
        replay = await second.post("/two-factor/verify-totp", json={"code": code})
        assert replay.json()["error"]["code"] == "TWO_FACTOR_INVALID_CODE"
    async with app.client() as first, app.client() as second:
        await challenged(first, second)
        body = {"code": backup[0]}
        used = await first.post("/two-factor/verify-backup-code", json=body)
        assert used.status_code == 200, used.text
        replay = await second.post("/two-factor/verify-backup-code", json=body)
        assert replay.json()["error"]["code"] == "TWO_FACTOR_INVALID_CODE"


async def test_a_two_factor_email_code_works_once() -> None:
    app = full_app(rate_limit={"enabled": False})
    async with app.client() as http:
        await app.verified_user(http)
        await two_factor_on(app, http)
    async with app.client() as first, app.client() as second:
        await challenged(first, second)
        assert (await first.post("/two-factor/send-otp")).status_code == 200
        body = {"code": await app.emailed("otp", r"\b\d{6}\b")}
        used = await first.post("/two-factor/verify-otp", json=body)
        assert used.status_code == 200, used.text
        replay = await second.post("/two-factor/verify-otp", json=body)
        assert replay.json()["error"]["code"] == "TWO_FACTOR_INVALID_CODE"


async def test_a_passkey_assertion_works_once() -> None:
    app = full_app(rate_limit={"enabled": False})
    device = SoftAuthenticator(origin=TEST_BASE_URL)
    async with app.client() as http:
        await app.verified_user(http)
        options = (await http.post("/passkey/register/options")).json()
        added = await http.post(
            "/passkey/register/verify", json={"response": device.create(options)}
        )
        assert added.status_code == 200, added.text
    async with app.client() as browser, app.client() as attacker:
        options = (await browser.post("/passkey/sign-in/options")).json()
        assertion = {"response": device.get(options)}
        used = await browser.post("/passkey/sign-in/verify", json=assertion)
        assert used.status_code == 200, used.text
        replay = await browser.post("/passkey/sign-in/verify", json=assertion)
        assert replay.status_code in (400, 401), replay.text
        # Another browser has no challenge cookie for it.
        await attacker.post("/passkey/sign-in/options")
        stolen = await attacker.post("/passkey/sign-in/verify", json=assertion)
        assert stolen.status_code in (400, 401), stolen.text
        assert (await attacker.get("/session")).json() is None


async def test_magic_links_and_sign_in_codes_work_once() -> None:
    app = full_app(rate_limit={"enabled": False})
    async with app.client() as http:
        await app.verified_user(http)
    async with app.client() as first, app.client() as second:
        await first.post("/magic-link/send", json={"email": "ada@example.com"})
        link = await app.emailed("magic_link", r"https?://\S+")
        assert (await first.get(link)).status_code == 302
        replay = await second.get(link)
        assert replay.json()["error"]["code"] == "TOKEN_INVALID"
        body = {"email": "ada@example.com", "type": "sign_in"}
        await first.post("/email-otp/send", json=body)
        body["otp"] = await app.emailed("otp", r"\b\d{6}\b")
        assert (await first.post("/email-otp/verify", json=body)).status_code == 200
        replay = await second.post("/email-otp/verify", json=body)
        assert replay.json()["error"]["code"] == "EMAIL_OTP_INVALID"
        assert (await second.get("/session")).json() is None


async def test_an_invitation_works_once_and_only_for_its_email() -> None:
    app = full_app(rate_limit={"enabled": False})
    async with (
        app.client() as owner,
        app.client() as invitee,
        app.client() as other,
    ):
        await app.verified_user(owner, "owner@example.com")
        await app.verified_user(invitee, "bob@example.com")
        await app.verified_user(other, "eve@example.com")
        created = await owner.post(
            "/organization/create", json={"name": "Acme", "slug": "acme"}
        )
        org_id = created.json()["id"]
        invited = await owner.post(
            "/organization/invite-member",
            json={"organization_id": org_id, "email": "bob@example.com"},
        )
        assert invited.status_code == 200, invited.text
        link = await app.emailed("invitation", r"https?://\S+", "bob@example.com")
        query = parse_qs(urlsplit(link).query)
        body = {"invitation_id": query["invitation_id"][0], "token": query["token"][0]}
        # A forwarded email: another signed-in user cannot use it.
        taken = await other.post("/organization/accept-invitation", json=body)
        assert taken.json()["error"]["code"] == "ORG_INVITATION_INVALID"
        accepted = await invitee.post("/organization/accept-invitation", json=body)
        assert accepted.status_code == 200, accepted.text
        replay = await invitee.post("/organization/accept-invitation", json=body)
        assert replay.json()["error"]["code"] == "ORG_INVITATION_INVALID"
        members = await other.get(
            "/organization/get", params={"organization_id": org_id}
        )
        assert members.json()["error"]["code"] == "ORG_NOT_A_MEMBER"
