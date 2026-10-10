"""Rate limits (CONTRACTS 10.2) and replay of single-use secrets."""

from __future__ import annotations

import pytest

from .conftest import PASSWORD, REDIRECT, full_app, oauth_client, oauth_code


async def test_sign_in_limit_with_retry_after_ignores_spoofed_ips() -> None:
    app = full_app()
    async with app.client() as http:
        responses = [
            await http.post(
                "/sign-in/email",
                json={"email": f"user{i}@example.com", "password": "wrong password"},
                # No trusted_proxies, so the header must be ignored.
                headers={"x-forwarded-for": f"203.0.113.{i}"},
            )
            for i in range(6)
        ]
    assert [r.status_code for r in responses] == [401] * 5 + [429]
    limited = responses[-1]
    assert int(limited.headers["retry-after"]) > 0
    assert limited.json()["error"]["code"] == "RATE_LIMITED"


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/sign-in/email", {"password": "wrong password"}),
        ("/request-password-reset", {"redirect_to": "/reset"}),
    ],
)
async def test_per_email_limits_hold_across_rotating_ips(
    path: str, body: dict[str, str]
) -> None:
    app = full_app()
    statuses: list[int] = []
    for i in range(11):
        async with app.client(ip=f"198.51.100.{i + 1}") as http:
            response = await http.post(path, json={"email": "ada@example.com", **body})
            statuses.append(response.status_code)
    assert 429 not in statuses[:10]
    assert statuses[10] == 429


@pytest.mark.skip(reason="P4 (/magic-link/send, /email-otp/send) has not merged")
async def test_per_email_limits_on_magic_link_and_otp() -> None:
    raise AssertionError("covered once P4 merges")


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
        exchange = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT,
            "client_id": client_id,
        }
        tokens = (await http.post("/oauth2/token", data=exchange)).json()
        replay = await http.post("/oauth2/token", data=exchange)
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
        first = (
            await http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": REDIRECT,
                    "client_id": client_id,
                },
            )
        ).json()

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


@pytest.mark.skip(
    reason="P2 (OTPs, TOTP, backup codes), P3 (passkey challenges) and P5"
    " (invitations) have not merged"
)
async def test_second_factor_and_invitation_replay() -> None:
    raise AssertionError("covered once P2, P3 and P5 merge")


@pytest.mark.skip(reason="P6 (bans) has not merged")
async def test_banned_users_are_rejected_on_every_credential() -> None:
    raise AssertionError("covered once P6 merges")
