"""Two-factor authentication (work package P2): setup, the sign-in challenge, replay
rules, backup codes, trusted devices, rate limits and the email OTP fallback."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import ConfigError
from gotauth.crypto import totp
from gotauth.plugins.two_factor import two_factor
from gotauth.plugins.two_factor._plugin import _use_totp
from gotauth.testing import (
    fake_clock,
    fake_mailer,
    load_vectors,
    make_auth,
    make_client,
    make_context,
)

PASSWORD = "correct horse battery"
EMAIL = "ada@example.com"


@dataclass
class World:
    auth: Any  # Any: GotAuth
    http: httpx.AsyncClient
    clock: Any  # Any: ManualClock
    mailer: Any  # Any: CapturingMailer
    user_id: str
    secret: str = ""
    backup_codes: tuple[str, ...] = ()

    def code(self, secret: str | None = None) -> str:
        return totp(secret or self.secret, at=self.clock.now())

    async def sign_in(
        self, http: httpx.AsyncClient | None = None, **extra: Any
    ) -> httpx.Response:
        client = http or self.http
        client.cookies.delete("gotauth.session_token")
        return await client.post(
            "/sign-in/email", json={"email": EMAIL, "password": PASSWORD, **extra}
        )

    async def enable(self) -> None:
        started = await self.http.post(
            "/two-factor/enable", json={"password": PASSWORD}
        )
        assert started.status_code == 200, started.text
        uri = started.json()["totp_uri"]
        assert uri.startswith("otpauth://totp/")
        self.secret = parse_qs(urlsplit(uri).query)["secret"][0]
        self.backup_codes = tuple(started.json()["backup_codes"])
        confirmed = await self.http.post(
            "/two-factor/verify-totp", json={"code": self.code()}
        )
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json() == {"status": "enabled"}
        self.clock.advance("30s")  # the next code is a new step


async def world(auth_options: dict[str, Any] | None = None, **options: Any) -> World:
    clock = fake_clock()
    mailer = fake_mailer()
    auth: Any = make_auth(
        clock=clock,
        mailer=mailer,
        email_password={"require_email_verification": False},
        plugins=[two_factor(**options)],
        **(auth_options or {}),
    )
    http = make_client(auth)
    signed_up = await http.post(
        "/sign-up/email", json={"email": EMAIL, "password": PASSWORD}
    )
    assert signed_up.status_code == 200, signed_up.text
    user = await auth.database.find_one("user", [])
    return World(auth=auth, http=http, clock=clock, mailer=mailer, user_id=user["id"])


# ---------------------------------------------------------------- vectors


async def _ctx_with_row(secret: str, moment: datetime | None = None) -> Any:
    """A fake context with the plugin, one user and a confirmed two-factor row."""
    ctx = make_context(
        plugins=[two_factor()], clock=fake_clock(moment) if moment else None
    )
    user = await ctx.auth.create_user_record(ctx, {"email": EMAIL})
    row = await ctx.adapter.create(
        "two_factor",
        {
            "id": "tfa_1",
            "user_id": user.id,
            "secret_enc": ctx.crypto.encrypt(secret, purpose="two_factor_secret"),
            "backup_code_hashes": [],
            "verified_at": ctx.clock.now(),
            "last_used_step": 0,
            "version": 0,
            "created_at": ctx.clock.now(),
        },
    )
    return ctx, user, row


async def test_rfc_6238_sha1_vectors_verify() -> None:
    for case in load_vectors("totp"):
        if case["algorithm"] != "SHA1":
            continue
        moment = datetime.fromtimestamp(case["unix_time"], tz=UTC)
        ctx, _, row = await _ctx_with_row(case["secret_b32"], moment)
        # A 6-digit code is the last 6 digits of the 8-digit vector.
        await _use_totp(ctx, row, case["totp"][-6:])


# ---------------------------------------------------------------- the flow


async def test_setup_then_the_sign_in_challenge() -> None:
    w = await world()
    started = await w.http.post("/two-factor/enable", json={"password": PASSWORD})
    w.secret = parse_qs(urlsplit(started.json()["totp_uri"]).query)["secret"][0]
    # Not active until a code is confirmed.
    assert "session" in (await w.sign_in()).json()
    confirmed = await w.http.post("/two-factor/verify-totp", json={"code": w.code()})
    assert confirmed.json() == {"status": "enabled"}
    me = await w.auth.database.find_one("user", [])
    assert me["two_factor_enabled"] is True
    w.clock.advance("30s")
    challenged = await w.sign_in()
    assert challenged.json() == {
        "challenge": {"type": "two_factor", "methods": ["totp", "backup_code"]}
    }
    assert "gotauth.session_token=" not in challenged.headers.get("set-cookie", "")
    done = await w.http.post("/two-factor/verify-totp", json={"code": w.code()})
    assert done.status_code == 200, done.text
    assert done.json()["user"]["id"] == w.user_id
    assert "gotauth.session_token=" in done.headers["set-cookie"]


async def test_remember_me_false_gives_a_browser_session_cookie() -> None:
    w = await world()
    await w.enable()
    await w.sign_in(remember_me=False)
    done = await w.http.post("/two-factor/verify-totp", json={"code": w.code()})
    cookie = next(
        c for c in done.headers.get_list("set-cookie") if "session_token=" in c
    )
    assert "Max-Age" not in cookie and "Expires" not in cookie


async def test_a_code_works_once_per_step() -> None:
    w = await world()
    await w.enable()
    await w.sign_in()
    code = w.code()
    assert (
        await w.http.post("/two-factor/verify-totp", json={"code": code})
    ).status_code == 200
    await w.sign_in()
    again = await w.http.post("/two-factor/verify-totp", json={"code": code})
    assert again.status_code == 401
    assert again.json()["error"]["code"] == "TWO_FACTOR_INVALID_CODE"
    # An earlier step is refused too.
    earlier = totp(w.secret, at=w.clock.now() - timedelta(seconds=30))
    old = await w.http.post("/two-factor/verify-totp", json={"code": earlier})
    assert old.status_code == 401


async def test_the_challenge_cookie_must_be_valid() -> None:
    w = await world()
    await w.enable()
    await w.sign_in()
    w.clock.advance("11m")
    late = await w.http.post("/two-factor/verify-totp", json={"code": w.code()})
    assert late.json()["error"]["code"] == "TOKEN_EXPIRED"
    async with make_client(w.auth) as other:
        other.cookies.set("gotauth.challenge", "tampered")
        bad = await other.post("/two-factor/verify-backup-code", json={"code": "x"})
        assert bad.json()["error"]["code"] == "TOKEN_INVALID"
    async with make_client(w.auth) as other:
        missing = await other.post("/two-factor/verify-backup-code", json={"code": "x"})
        assert missing.json()["error"]["code"] == "TOKEN_INVALID"


async def test_backup_codes_work_once() -> None:
    w = await world()
    await w.enable()
    code = w.backup_codes[0]
    await w.sign_in()
    ok = await w.http.post("/two-factor/verify-backup-code", json={"code": code})
    assert ok.status_code == 200, ok.text
    await w.sign_in()
    again = await w.http.post("/two-factor/verify-backup-code", json={"code": code})
    assert again.status_code == 401


async def test_a_backup_code_is_not_used_twice_concurrently() -> None:
    w = await world()
    await w.enable()
    code = w.backup_codes[1]
    clients = [make_client(w.auth) for _ in range(4)]
    for client in clients:
        await w.sign_in(client)
    results = await asyncio.gather(
        *(
            client.post("/two-factor/verify-backup-code", json={"code": code})
            for client in clients
        )
    )
    assert sorted(r.status_code for r in results) == [200, 401, 401, 401]


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(guess=st.text(min_size=1, max_size=20))
async def test_random_strings_are_never_backup_codes(guess: str) -> None:
    w = await world()
    await w.enable()
    await w.sign_in()
    if guess.strip() in w.backup_codes:
        return
    response = await w.http.post("/two-factor/verify-backup-code", json={"code": guess})
    assert response.status_code in (401, 400)


async def test_trusted_devices() -> None:
    w = await world()
    await w.enable()
    await w.sign_in()
    trusted = await w.http.post(
        "/two-factor/verify-totp", json={"code": w.code(), "trust_device": True}
    )
    assert "gotauth.two_factor_trust=" in trusted.headers["set-cookie"]
    w.clock.advance("29d")
    assert "session" in (await w.sign_in()).json()  # day 29: no second step
    w.clock.advance("2d")
    assert "challenge" in (await w.sign_in()).json()  # day 31


async def test_a_trust_cookie_is_for_one_user_and_one_setup() -> None:
    w = await world()
    await w.enable()
    await w.sign_in()
    await w.http.post(
        "/two-factor/verify-totp", json={"code": w.code(), "trust_device": True}
    )
    trust = w.http.cookies.get("gotauth.two_factor_trust")
    # Turning two-factor off and on again drops trusted devices.
    disabled = await w.http.post("/two-factor/disable", json={"password": PASSWORD})
    assert disabled.status_code == 200, disabled.text
    w.clock.advance("30s")
    await w.enable()
    w.http.cookies.set("gotauth.two_factor_trust", trust or "")
    assert "challenge" in (await w.sign_in()).json()


async def test_passkey_sign_ins_skip_the_challenge() -> None:
    ctx, user, _ = await _ctx_with_row("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    default = two_factor().sign_in_interceptors[0]
    strict = two_factor(skip_for_methods=()).sign_in_interceptors[0]
    assert await default(ctx, user, "passkey") is None
    assert await default(ctx, user, "password") is not None
    assert await strict(ctx, user, "passkey") is not None


async def test_verify_attempts_are_capped_per_user_across_ips() -> None:
    # The test client is the trusted proxy; each attempt comes from another IP.
    w = await world(
        auth_options={
            "advanced": {
                "ip_headers": ("x-forwarded-for",),
                "trusted_proxies": ("127.0.0.1",),
            }
        }
    )
    await w.enable()
    w.clock.advance("16m")  # the setup confirmation counted in the last window
    await w.sign_in()
    statuses: list[int] = []
    for attempt in range(11):
        response = await w.http.post(
            "/two-factor/verify-totp",
            json={"code": "000000"},
            headers={"x-forwarded-for": f"10.0.0.{attempt}"},
        )
        statuses.append(response.status_code)
    assert statuses[-1] == 429
    assert statuses[:10].count(429) == 0


async def test_enforced_users_set_up_during_sign_in_and_cannot_disable() -> None:
    w = await world(enforce=lambda user: True)
    challenged = await w.sign_in()
    assert challenged.json() == {
        "challenge": {"type": "two_factor_setup", "methods": ["totp"]}
    }
    started = await w.http.post("/two-factor/enable", json={})
    assert started.status_code == 200, started.text
    w.secret = parse_qs(urlsplit(started.json()["totp_uri"]).query)["secret"][0]
    done = await w.http.post("/two-factor/verify-totp", json={"code": w.code()})
    assert done.status_code == 200, done.text
    assert "session" in done.json()
    refused = await w.http.post("/two-factor/disable", json={"password": PASSWORD})
    assert refused.status_code == 403


async def test_disable_and_regenerate_need_a_fresh_session_and_password() -> None:
    w = await world()
    await w.enable()
    wrong = await w.http.post("/two-factor/disable", json={"password": "nope"})
    assert wrong.status_code == 401
    regenerated = await w.http.post("/two-factor/regenerate-backup-codes")
    assert regenerated.status_code == 200
    assert set(regenerated.json()["backup_codes"]).isdisjoint(w.backup_codes)
    w.clock.advance("2d")
    stale = await w.http.post("/two-factor/disable", json={"password": PASSWORD})
    assert stale.json()["error"]["code"] == "FRESH_SESSION_REQUIRED"


async def test_users_cannot_set_the_flag_themselves() -> None:
    w = await world()
    response = await w.http.patch("/user", json={"two_factor_enabled": True})
    assert response.status_code == 400
    me = await w.auth.database.find_one("user", [])
    assert me["two_factor_enabled"] is False


async def test_no_secret_or_code_is_stored_in_plain_text() -> None:
    w = await world(email_otp=True)
    await w.enable()
    await w.sign_in()
    await w.http.post("/two-factor/send-otp")
    otp = _otp(w)
    dump = repr(
        [
            await w.auth.database.find_many(model, [])
            for model in ("two_factor", "verification", "user")
        ]
    )
    for secret in (w.secret, otp, *(c.replace("-", "") for c in w.backup_codes)):
        assert secret not in dump.replace("-", "")


# ---------------------------------------------------------------- email OTP


def _otp(w: World) -> str:
    found = re.search(r"\b\d{6}\b", w.mailer.last("otp", EMAIL).text)
    assert found is not None
    return found.group(0)


async def test_email_otp_and_its_attempt_limit() -> None:
    w = await world(email_otp=True)
    await w.enable()
    challenged = await w.sign_in()
    assert "email_otp" in challenged.json()["challenge"]["methods"]
    await w.http.post("/two-factor/send-otp")
    otp = _otp(w)
    wrong = "000000" if otp != "000000" else "111111"
    for _ in range(5):
        failed = await w.http.post("/two-factor/verify-otp", json={"code": wrong})
        assert failed.status_code == 401
    w.clock.advance("61s")  # past the 5-per-minute IP limit, not the user cap
    late = await w.http.post("/two-factor/verify-otp", json={"code": otp})
    assert late.status_code == 401  # the 5th failure deleted the code
    await w.http.post("/two-factor/send-otp")
    otp = _otp(w)
    ok = await w.http.post("/two-factor/verify-otp", json={"code": otp})
    assert ok.status_code == 200, ok.text


def test_email_otp_needs_an_email_sender_off_localhost() -> None:
    with pytest.raises(ConfigError):
        make_auth(
            base_url="https://auth.example.com",
            email_sender=None,
            mailer=None,
            plugins=[two_factor(email_otp=True)],
        )


async def test_two_users_can_hold_the_same_email_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gotauth.crypto import DefaultCryptoKit

    real = DefaultCryptoKit.new_otp
    monkeypatch.setattr(
        DefaultCryptoKit,
        "new_otp",
        lambda self, digits=6: "424242" if digits == 6 else real(self, digits),
    )
    w = await world(email_otp=True)
    await w.enable()
    bob = make_client(w.auth)
    signed_up = await bob.post(
        "/sign-up/email", json={"email": "bob@example.com", "password": PASSWORD}
    )
    assert signed_up.status_code == 200
    bob_secret = parse_qs(
        urlsplit(
            (await bob.post("/two-factor/enable", json={"password": PASSWORD})).json()[
                "totp_uri"
            ]
        ).query
    )["secret"][0]
    await bob.post("/two-factor/verify-totp", json={"code": w.code(bob_secret)})
    for client, email in ((w.http, EMAIL), (bob, "bob@example.com")):
        client.cookies.delete("gotauth.session_token")
        await client.post("/sign-in/email", json={"email": email, "password": PASSWORD})
        sent = await client.post("/two-factor/send-otp")
        assert sent.status_code == 200, sent.text
    for client in (w.http, bob):
        done = await client.post("/two-factor/verify-otp", json={"code": "424242"})
        assert done.status_code == 200, done.text


# ---------------------------------------------------------------- review fixes


async def test_a_stale_challenge_cookie_does_not_block_the_session() -> None:
    w = await world()
    await w.enable()
    async with make_client(w.auth) as other:
        await w.sign_in(other)
        stale = other.cookies.get("gotauth.challenge")
    assert stale
    w.http.cookies.set("gotauth.challenge", stale)  # next to the fresh session
    w.clock.advance("11m")  # the challenge expired; the session is still fresh
    await w.http.post("/two-factor/disable", json={"password": PASSWORD})
    again = await w.http.post("/two-factor/enable", json={"password": PASSWORD})
    assert again.status_code == 200, again.text


async def test_a_wrong_second_factor_is_a_failed_sign_in() -> None:
    events: list[Any] = []

    async def record(event: Any) -> None:
        events.append(event)

    w = await world(auth_options={"on_event": record})
    await w.enable()
    await w.sign_in()
    await w.http.post("/two-factor/verify-totp", json={"code": "000000"})
    await w.http.post("/two-factor/verify-backup-code", json={"code": "00000-00000"})
    await w.auth.drain()
    failed = [e for e in events if e.type == "sign_in.failed"]
    assert len(failed) == 2
    assert {e.data["reason"] for e in failed} == {"invalid_second_factor"}


async def test_password_checks_are_capped_per_user_across_ips() -> None:
    w = await world(
        auth_options={
            "advanced": {
                "ip_headers": ("x-forwarded-for",),
                "trusted_proxies": ("127.0.0.1",),
            }
        }
    )
    await w.enable()
    statuses = [
        (
            await w.http.post(
                "/two-factor/disable",
                json={"password": "wrong"},
                headers={"x-forwarded-for": f"10.0.1.{attempt}"},
            )
        ).status_code
        for attempt in range(21)
    ]
    assert statuses[-1] == 429


async def test_the_authenticator_uri_is_percent_encoded() -> None:
    w = await world(issuer="Acme Corp")
    started = await w.http.post("/two-factor/enable", json={"password": PASSWORD})
    uri = started.json()["totp_uri"]
    assert uri.startswith("otpauth://totp/Acme%20Corp%3Aada%40example.com?")
    assert "issuer=Acme%20Corp" in uri


async def test_one_email_code_is_live_at_a_time() -> None:
    w = await world(email_otp=True)
    await w.enable()
    await w.sign_in()
    await w.http.post("/two-factor/send-otp")
    await w.http.post("/two-factor/send-otp")
    rows = await w.auth.database.find_many("verification", [])
    assert len([r for r in rows if r["identifier"].startswith("two_factor_otp:")]) == 1
