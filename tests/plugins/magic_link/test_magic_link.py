"""Passwordless sign-in (work package P4): magic links and email OTPs, single use,
attempt limits and the enumeration rules of CONTRACTS 9.1."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import ConfigError, Where
from gotauth.plugins.magic_link import email_otp, magic_link
from gotauth.testing import fake_clock, fake_mailer, make_auth, make_client

PASSWORD = "correct horse battery"
ADA = "ada@example.com"


@dataclass
class World:
    auth: Any  # Any: GotAuth
    http: httpx.AsyncClient
    clock: Any  # Any: ManualClock
    mailer: Any  # Any: CapturingMailer

    def link(self, email: str = ADA) -> str:
        found = re.search(r"https?://\S+", self.mailer.last("magic_link", email).text)
        assert found is not None
        return found.group(0)

    def code(self, email: str = ADA) -> str:
        found = re.search(r"\b\d{6}\b", self.mailer.last("otp", email).text)
        assert found is not None
        return found.group(0)

    async def users(self) -> set[str]:
        return {row["email"] for row in await self.auth.database.find_many("user", [])}


def world(**options: Any) -> World:
    clock = fake_clock()
    mailer = fake_mailer()
    plugins = options.pop("plugins", None) or [magic_link(), email_otp()]
    auth: Any = make_auth(
        clock=clock,
        mailer=mailer,
        email_password={"require_email_verification": False},
        plugins=plugins,
        **options,
    )
    return World(auth=auth, http=make_client(auth), clock=clock, mailer=mailer)


async def visit(w: World, url: str) -> httpx.Response:
    parts = urlsplit(url)
    return await w.http.get(
        parts.path.removeprefix("/api/auth"),
        params={k: v[0] for k, v in parse_qs(parts.query).items()},
        follow_redirects=False,
    )


# ---------------------------------------------------------------- magic link


async def test_a_magic_link_signs_in_and_redirects() -> None:
    w = world()
    sent = await w.http.post(
        "/magic-link/send", json={"email": ADA, "callback_url": "/dashboard"}
    )
    assert sent.json() == {"status": "ok"}
    response = await visit(w, w.link())
    assert response.status_code == 302
    assert response.headers["location"] == "/dashboard"
    assert "gotauth.session_token=" in response.headers["set-cookie"]
    session = await w.http.get("/session")
    assert session.json()["user"]["email"] == ADA
    assert session.json()["user"]["email_verified"] is True


async def test_a_link_works_once_and_expires() -> None:
    w = world()
    await w.http.post("/magic-link/send", json={"email": ADA})
    url = w.link()
    assert (await visit(w, url)).status_code == 302
    again = await visit(w, url)
    assert again.json()["error"]["code"] == "TOKEN_INVALID"
    w.clock.advance("61s")  # past the send cooldown
    await w.http.post("/magic-link/send", json={"email": ADA})
    late_url = w.link()
    w.clock.advance("11m")
    late = await visit(w, late_url)
    assert late.json()["error"]["code"] == "TOKEN_EXPIRED"


async def test_two_concurrent_visits_give_one_session() -> None:
    w = world()
    await w.http.post("/magic-link/send", json={"email": ADA})
    url = w.link()
    clients = [make_client(w.auth) for _ in range(2)]
    parts = urlsplit(url)
    results = await asyncio.gather(
        *(
            c.get(
                parts.path.removeprefix("/api/auth"),
                params={k: v[0] for k, v in parse_qs(parts.query).items()},
                follow_redirects=False,
            )
            for c in clients
        )
    )
    assert sorted(r.status_code for r in results) == [302, 400]
    assert len(await w.auth.database.find_many("session", [])) == 1


async def test_failures_go_to_the_error_callback() -> None:
    w = world()
    await w.http.post(
        "/magic-link/send",
        json={"email": ADA, "error_callback_url": "/sign-in"},
    )
    url = w.link()
    w.clock.advance("11m")
    response = await visit(w, url)
    assert response.status_code == 302
    assert response.headers["location"] == "/sign-in?error=TOKEN_EXPIRED"


async def test_an_outside_callback_is_refused_and_nothing_is_sent() -> None:
    w = world()
    response = await w.http.post(
        "/magic-link/send",
        json={"email": ADA, "callback_url": "https://evil.example"},
    )
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    await w.auth.drain()
    assert w.mailer.sent == []


async def test_without_sign_up_an_unknown_email_gets_nothing() -> None:
    w = world(plugins=[magic_link(allow_sign_up=False)])
    await w.http.post("/sign-up/email", json={"email": ADA, "password": PASSWORD})
    answers = []
    for email in (ADA, "nobody@example.com"):
        response = await w.http.post("/magic-link/send", json={"email": email})
        answers.append((response.status_code, response.content))
    assert answers[0] == answers[1]
    await w.auth.drain()
    assert {m.to for m in w.mailer.sent if m.kind == "magic_link"} == {ADA}
    assert "nobody@example.com" not in await w.users()


async def test_a_repeat_send_inside_the_cooldown_sends_nothing() -> None:
    w = world()
    for _ in range(2):
        assert (await w.http.post("/magic-link/send", json={"email": ADA})).json() == {
            "status": "ok"
        }
    assert len([m for m in w.mailer.sent if m.kind == "magic_link"]) == 1


# ---------------------------------------------------------------- email OTP


async def test_an_email_code_signs_in_once() -> None:
    w = world()
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "sign_in"})
    code = w.code()
    signed_in = await w.http.post(
        "/email-otp/verify", json={"email": ADA, "otp": code, "type": "sign_in"}
    )
    assert signed_in.status_code == 200, signed_in.text
    assert signed_in.json()["user"]["email"] == ADA
    again = await w.http.post(
        "/email-otp/verify", json={"email": ADA, "otp": code, "type": "sign_in"}
    )
    assert again.json()["error"]["code"] == "EMAIL_OTP_INVALID"


async def test_five_wrong_codes_end_the_code() -> None:
    w = world()
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "sign_in"})
    code = w.code()
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        failed = await w.http.post(
            "/email-otp/verify", json={"email": ADA, "otp": wrong, "type": "sign_in"}
        )
        assert failed.json()["error"]["code"] == "EMAIL_OTP_INVALID"
        w.clock.advance("13s")  # stay under the per-IP limit
    late = await w.http.post(
        "/email-otp/verify", json={"email": ADA, "otp": code, "type": "sign_in"}
    )
    assert late.json()["error"]["code"] == "EMAIL_OTP_INVALID"


async def test_a_code_is_for_its_type_and_its_email() -> None:
    w = world()
    await w.http.post("/sign-up/email", json={"email": ADA, "password": PASSWORD})
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "verify_email"})
    code = w.code()
    wrong_type = await w.http.post(
        "/email-otp/verify", json={"email": ADA, "otp": code, "type": "sign_in"}
    )
    assert wrong_type.json()["error"]["code"] == "EMAIL_OTP_INVALID"
    verified = await w.http.post(
        "/email-otp/verify", json={"email": ADA, "otp": code, "type": "verify_email"}
    )
    assert verified.json() == {"status": "verified"}
    row = await w.auth.database.find_one("user", [Where("email", ADA)])
    assert row["email_verified"] is True


async def test_two_users_can_hold_the_same_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gotauth.crypto import DefaultCryptoKit

    monkeypatch.setattr(DefaultCryptoKit, "new_otp", lambda self, digits=6: "424242")
    w = world()
    for email in (ADA, "bob@example.com"):
        await w.http.post("/email-otp/send", json={"email": email, "type": "sign_in"})
    for email in (ADA, "bob@example.com"):
        async with make_client(w.auth) as browser:
            done = await browser.post(
                "/email-otp/verify",
                json={"email": email, "otp": "424242", "type": "sign_in"},
            )
            assert done.status_code == 200, done.text


async def test_reset_password_with_a_code() -> None:
    w = world()
    await w.http.post("/sign-up/email", json={"email": ADA, "password": PASSWORD})
    old_session = w.http.cookies.get("gotauth.session_token")
    async with make_client(w.auth) as other:
        await other.post(
            "/email-otp/send", json={"email": ADA, "type": "reset_password"}
        )
        code = w.code()
        short = await other.post(
            "/email-otp/verify",
            json={
                "email": ADA,
                "otp": code,
                "type": "reset_password",
                "new_password": "x",
            },
        )
        assert short.json()["error"]["code"] == "PASSWORD_TOO_SHORT"
        reset = await other.post(
            "/email-otp/verify",
            json={
                "email": ADA,
                "otp": code,
                "type": "reset_password",
                "new_password": "a brand new password",
            },
        )
        assert reset.json() == {"status": "ok"}
    assert old_session and (await w.http.get("/session")).json() is None
    old = await w.http.post("/sign-in/email", json={"email": ADA, "password": PASSWORD})
    assert old.status_code == 401
    new = await w.http.post(
        "/sign-in/email", json={"email": ADA, "password": "a brand new password"}
    )
    assert new.status_code == 200


async def test_send_answers_the_same_for_every_email_and_type() -> None:
    w = world(plugins=[email_otp(allow_sign_up=False)])
    await w.http.post("/sign-up/email", json={"email": ADA, "password": PASSWORD})
    answers: set[bytes] = set()
    for email in (ADA, "nobody@example.com"):
        for kind in ("sign_in", "verify_email", "reset_password"):
            w.clock.advance("13s")  # stay under the per-IP limit
            response = await w.http.post(
                "/email-otp/send", json={"email": email, "type": kind}
            )
            answers.add(response.content)
    assert answers == {b'{"status":"ok"}'}
    await w.auth.drain()
    assert {m.to for m in w.mailer.sent if m.kind == "otp"} == {ADA}


async def test_eleven_sends_for_one_email_are_limited_across_ips() -> None:
    w = world(
        advanced={"ip_headers": ("x-forwarded-for",), "trusted_proxies": ("127.0.0.1",)}
    )
    statuses = [
        (
            await w.http.post(
                "/email-otp/send",
                json={"email": ADA, "type": "sign_in"},
                headers={"x-forwarded-for": f"10.0.2.{attempt}"},
            )
        ).status_code
        for attempt in range(11)
    ]
    assert statuses[:10] == [200] * 10 and statuses[10] == 429


def test_an_email_sender_is_needed_off_localhost() -> None:
    for plugin in (magic_link(), email_otp()):
        with pytest.raises(ConfigError):
            make_auth(
                base_url="https://auth.example.com",
                email_sender=None,
                mailer=None,
                plugins=[plugin],
            )


async def test_no_token_or_code_is_stored_in_plain_text() -> None:
    w = world()
    await w.http.post("/magic-link/send", json={"email": ADA})
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "sign_in"})
    token = parse_qs(urlsplit(w.link()).query)["token"][0]
    dump = repr(await w.auth.database.find_many("verification", []))
    assert token not in dump and w.code() not in dump


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    guesses=st.lists(st.text(alphabet="0123456789", min_size=6, max_size=6), max_size=8)
)
async def test_at_most_one_success_and_none_after_five_failures(
    guesses: list[str],
) -> None:
    w = world()
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "sign_in"})
    code = w.code()
    failures = successes = 0
    for guess in [*guesses, code]:
        w.clock.advance("13s")
        response = await w.http.post(
            "/email-otp/verify", json={"email": ADA, "otp": guess, "type": "sign_in"}
        )
        if response.status_code == 200:
            successes += 1
            assert failures < 5
        else:
            failures += 1
    assert successes <= 1


# ---------------------------------------------------------------- review fixes


async def test_a_pre_registered_account_is_claimed_cleanly() -> None:
    # Someone signs up with the victim's email before the victim (pre-account
    # hijacking); the victim then signs in by link.
    w = world()
    async with make_client(w.auth) as attacker:
        await attacker.post(
            "/sign-up/email", json={"email": ADA, "password": "attacker's password"}
        )
        assert (await attacker.get("/session")).json() is not None
        await w.http.post("/magic-link/send", json={"email": ADA})
        assert (await visit(w, w.link())).status_code == 302
        assert (await attacker.get("/session")).json() is None
        again = await attacker.post(
            "/sign-in/email", json={"email": ADA, "password": "attacker's password"}
        )
        assert again.status_code == 401
    assert (await w.http.get("/session")).json()["user"]["email"] == ADA


async def test_a_wrong_code_does_the_same_reads_for_any_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gotauth.storage.memory import _adapter

    calls: list[tuple[str, str]] = []
    for name in ("create", "find", "find_many", "update", "delete"):
        real = getattr(_adapter._Store, name)  # pyright: ignore[reportPrivateUsage]

        def record(
            self: Any, model: str, *a: Any, _n: str = name, _r: Any = real
        ) -> Any:
            calls.append((_n, model))
            return _r(self, model, *a)

        monkeypatch.setattr(_adapter._Store, name, record)  # pyright: ignore[reportPrivateUsage]
    w = world(plugins=[email_otp(allow_sign_up=False)])
    await w.http.post("/sign-up/email", json={"email": ADA, "password": PASSWORD})
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "reset_password"})
    await w.auth.drain()
    seen = []
    for email in (ADA, "nobody@example.com"):
        w.clock.advance("13s")
        calls.clear()
        response = await w.http.post(
            "/email-otp/verify",
            json={
                "email": email,
                "otp": "000000",
                "type": "reset_password",
                "new_password": "a brand new password",
            },
        )
        assert response.json()["error"]["code"] == "EMAIL_OTP_INVALID"
        seen.append([c for c in calls if c[1] != "session"])
    assert seen[0] == seen[1]


async def test_concurrent_wrong_guesses_fail_closed() -> None:
    w = world()
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "sign_in"})
    code = w.code()
    wrong = "000000" if code != "000000" else "111111"
    clients = [make_client(w.auth) for _ in range(3)]
    await asyncio.gather(
        *(
            c.post(
                "/email-otp/verify",
                json={"email": ADA, "otp": wrong, "type": "sign_in"},
            )
            for c in clients
        )
    )
    rows = await w.auth.database.find_many("verification", [])
    remaining = [r for r in rows if r["identifier"] == f"email_otp:sign_in:{ADA}"]
    # Every wrong guess was counted, or the code is gone: never fewer than sent.
    assert not remaining or remaining[0]["attempts"] == 3


async def test_a_link_with_tracking_parameters_works() -> None:
    w = world()
    await w.http.post("/magic-link/send", json={"email": ADA})
    response = await visit(w, w.link() + "&utm_source=email")
    assert response.status_code == 302


async def test_a_refused_sign_in_goes_to_the_error_callback() -> None:
    from gotauth.contracts import AuthError, Plugin

    async def refuse(ctx: Any, user: Any, method: str) -> None:
        raise AuthError("FORBIDDEN", 403)

    w = world(
        plugins=[magic_link(), Plugin(id="refuse", sign_in_interceptors=(refuse,))]
    )
    await w.http.post(
        "/magic-link/send", json={"email": ADA, "error_callback_url": "/sign-in"}
    )
    response = await visit(w, w.link())
    assert response.headers["location"] == "/sign-in?error=FORBIDDEN"


async def test_a_code_reset_changes_an_existing_password_only() -> None:
    w = world()
    # A user without a password, as after a social sign-in.
    await w.auth.create_user_record(None, {"email": ADA, "email_verified": True})
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "reset_password"})
    await w.auth.drain()
    assert not [m for m in w.mailer.sent if m.kind == "otp"]


async def test_a_code_reset_notifies_and_drops_reset_links() -> None:
    w = world()
    await w.http.post("/sign-up/email", json={"email": ADA, "password": PASSWORD})
    await w.http.post(
        "/request-password-reset", json={"email": ADA, "redirect_to": "/reset"}
    )
    await w.auth.drain()
    link_rows = await w.auth.database.find_many("verification", [])
    assert any(r["identifier"].startswith("reset_password:") for r in link_rows)
    w.clock.advance("61s")
    await w.http.post("/email-otp/send", json={"email": ADA, "type": "reset_password"})
    reset = await w.http.post(
        "/email-otp/verify",
        json={
            "email": ADA,
            "otp": w.code(),
            "type": "reset_password",
            "new_password": "a brand new password",
        },
    )
    assert reset.json() == {"status": "ok"}
    rows = await w.auth.database.find_many("verification", [])
    assert not any(r["identifier"].startswith("reset_password:") for r in rows)
    assert w.mailer.last("security_notice", ADA) is not None
