"""Email + password over HTTP on a real GotAuth (C1 pipeline, C3 sessions)."""

from __future__ import annotations

from typing import Any

from gotauth.testing import fake_clock, fake_mailer, make_auth, make_client

from .conftest import PASSWORD, token_from


def build(**overrides: Any) -> tuple[Any, Any]:
    mailer = fake_mailer()
    return make_auth(mailer=mailer, **overrides), mailer


async def test_enumeration_bodies_are_byte_identical() -> None:
    auth, _ = build()
    async with make_client(auth) as client:
        await client.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        pairs = []
        for path, field in [
            ("/sign-up/email", {"password": PASSWORD}),
            ("/send-verification-email", {}),
            ("/request-password-reset", {"redirect_to": "/reset"}),
        ]:
            bodies = []
            for email in ("ada@example.com", "nobody@example.com"):
                response = await client.post(path, json={"email": email, **field})
                bodies.append((response.status_code, response.content))
            pairs.append(bodies)
        sign_in = []
        for email, password in [
            ("ghost@example.com", PASSWORD),  # never signed up
            ("ada@example.com", "wrong password"),
        ]:
            response = await client.post(
                "/sign-in/email", json={"email": email, "password": password}
            )
            sign_in.append((response.status_code, response.content))
    for existing, unknown in pairs:
        assert existing == unknown
    assert sign_in[0] == sign_in[1]
    assert sign_in[0][0] == 401


async def test_full_round_trip() -> None:
    auth, mailer = build()
    async with make_client(auth) as client:
        response = await client.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        assert response.json() == {"status": "verification_sent"}
        token = token_from(mailer.last("verify_email").data["url"])
        verified = await client.get(
            "/verify-email", params={"token": token, "callback_url": "/home"}
        )
        assert verified.status_code == 302
        assert verified.headers["location"] == "/home"
        signed_in = await client.post(
            "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        assert signed_in.status_code == 200, signed_in.text
        assert signed_in.json()["user"]["email_verified"] is True
        session = (await client.get("/session")).json()
        assert session["user"]["email"] == "ada@example.com"
        renamed = await client.patch("/user", json={"name": "Ada"})
        assert renamed.json()["name"] == "Ada"
        out = await client.post("/sign-out")
        assert out.json() == {"status": "ok"}
        assert (await client.get("/session")).json() is None


async def test_delete_user_with_a_json_body() -> None:
    auth, mailer = build(email_password={"require_email_verification": False})
    async with make_client(auth) as client:
        await client.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        wrong = await client.request(
            "DELETE", "/user", json={"password": "wrong password"}
        )
        assert wrong.status_code == 401
        deleted = await client.request("DELETE", "/user", json={"password": PASSWORD})
        assert deleted.json() == {"status": "ok"}
        assert (await client.get("/session")).json() is None
        again = await client.post(
            "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
    assert again.status_code == 401
    del mailer


async def test_untrusted_redirect_is_invalid_request() -> None:
    auth, _ = build()
    async with make_client(auth) as client:
        response = await client.post(
            "/request-password-reset",
            json={"email": "ada@example.com", "redirect_to": "https://evil.test/reset"},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


async def test_change_email_needs_a_recent_sign_in() -> None:
    # ASVS 7.5.1: a stolen day-old session must not be able to move the account.
    clock = fake_clock()
    auth, mailer = build(
        clock=clock, email_password={"require_email_verification": False}
    )
    async with make_client(auth) as client:
        signed_up = await client.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        assert signed_up.status_code == 200, signed_up.text
        clock.advance("2d")  # older than sessions.fresh_age (1 day), still valid
        stale = await client.post(
            "/change-email", json={"new_email": "new@example.com"}
        )
        assert stale.status_code == 403
        assert stale.json()["error"]["code"] == "FRESH_SESSION_REQUIRED"
        signed_in = await client.post(
            "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        assert signed_in.status_code == 200, signed_in.text
        fresh = await client.post(
            "/change-email", json={"new_email": "new@example.com"}
        )
        assert fresh.status_code == 200, fresh.text
        assert mailer.last("change_email", "new@example.com")


async def test_password_check_on_sign_up_reset_and_change() -> None:
    seen: list[tuple[str, str]] = []

    async def rule(password: str, email: str) -> str | None:
        seen.append((password, email))
        return "Too common." if password == "password123" else None

    auth, mailer = build(
        email_password={"require_email_verification": False, "password_check": rule}
    )
    async with make_client(auth) as client:
        # Sign-up: refused with the hook's message, the same for a new and an
        # existing email (CONTRACTS 9.1).
        refused = await client.post(
            "/sign-up/email",
            json={"email": "ada@example.com", "password": "password123"},
        )
        assert refused.status_code == 400
        assert refused.json()["error"] == {
            "code": "PASSWORD_REJECTED",
            "message": "Too common.",
            "details": None,
        }
        ok = await client.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        assert ok.status_code == 200, ok.text
        again = await client.post(
            "/sign-up/email",
            json={"email": "ada@example.com", "password": "password123"},
        )
        assert again.content == refused.content
        # Change: checked after the current password.
        changed = await client.post(
            "/change-password",
            json={"current_password": PASSWORD, "new_password": "password123"},
        )
        assert changed.json()["error"]["code"] == "PASSWORD_REJECTED"
        # Reset: a rejection keeps the link usable.
        await client.post(
            "/request-password-reset",
            json={"email": "ada@example.com", "redirect_to": "/reset"},
        )
        await auth.drain()
        token = token_from(mailer.last("reset_password", "ada@example.com").data["url"])
        rejected = await client.post(
            "/reset-password", json={"token": token, "new_password": "password123"}
        )
        assert rejected.json()["error"]["code"] == "PASSWORD_REJECTED"
        accepted = await client.post(
            "/reset-password", json={"token": token, "new_password": "a better one!"}
        )
        assert accepted.status_code == 200, accepted.text
    assert ("password123", "ada@example.com") in seen


async def test_a_failing_password_check_fails_closed() -> None:
    async def broken(password: str, email: str) -> str | None:
        raise RuntimeError("breach service down")

    auth, _ = build(
        email_password={"require_email_verification": False, "password_check": broken}
    )
    async with make_client(auth) as client:
        response = await client.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
    assert response.status_code == 500
    assert "breach service" not in response.text
    assert await auth.database.find_one("user", []) is None
