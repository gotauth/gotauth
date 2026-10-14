"""Account enumeration (CONTRACTS 9.1): same answers, and similar timing, for known
and unknown emails."""

from __future__ import annotations

import math
import statistics
import time
from collections.abc import Callable
from typing import Any

import pytest

from gotauth.crypto import crypto_kit
from gotauth.testing import TEST_SECRET

from .conftest import PASSWORD, full_app

UNKNOWN = "nobody@example.com"


async def test_same_status_and_body_for_known_and_unknown_emails() -> None:
    app = full_app()
    async with app.client() as http:
        await app.verified_user(http)
        http.cookies.clear()
        # Sign-up last: it creates the unknown account.
        cases = [
            ("/send-verification-email", {}),
            ("/request-password-reset", {"redirect_to": "/reset"}),
            ("/sign-up/email", {"password": PASSWORD}),
        ]
        for path, extra in cases:
            known = await http.post(path, json={"email": "ada@example.com", **extra})
            unknown = await http.post(path, json={"email": UNKNOWN, **extra})
            assert (known.status_code, known.content) == (
                unknown.status_code,
                unknown.content,
            ), path
        sign_in = [
            await http.post(
                "/sign-in/email", json={"email": email, "password": "wrong password"}
            )
            for email in ("ada@example.com", "ghost@example.com")
        ]
        assert sign_in[0].status_code == sign_in[1].status_code == 401
        assert sign_in[0].content == sign_in[1].content


async def test_magic_link_otp_and_invitations() -> None:
    # The same status and body whether or not the email has an account (9.1).

    from gotauth.plugins.magic_link import email_otp, magic_link
    from gotauth.plugins.organization import organization
    from gotauth.testing import fake_clock, make_auth, make_client

    clock = fake_clock()
    auth: Any = make_auth(
        clock=clock,
        email_password={"require_email_verification": False},
        plugins=[
            magic_link(allow_sign_up=False),
            email_otp(allow_sign_up=False),
            organization(),
        ],
    )
    async with make_client(auth) as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        org = await http.post(
            "/organization/create", json={"name": "Acme", "slug": "acme"}
        )
        org_id = org.json()["id"]
        cases = [
            ("/magic-link/send", {}),
            ("/email-otp/send", {"type": "sign_in"}),
            ("/email-otp/send", {"type": "reset_password"}),
        ]
        for path, extra in cases:
            answers = []
            for email in ("ada@example.com", UNKNOWN):
                clock.advance("61s")  # outside the send cooldown and the IP limit
                response = await http.post(path, json={"email": email, **extra})
                answers.append((response.status_code, response.content))
            assert answers[0] == answers[1], path
        async with make_client(auth) as other:  # an account that is not a member
            await other.post(
                "/sign-up/email",
                json={"email": "bob@example.com", "password": PASSWORD},
            )
        invited = []
        for email in ("bob@example.com", UNKNOWN):
            response = await http.post(
                "/organization/invite-member",
                json={"organization_id": org_id, "email": email},
            )
            assert response.status_code == 200, response.text
            body = response.json()
            invited.append((response.status_code, sorted(body), body["status"]))
        assert invited[0] == invited[1]


async def test_sign_in_does_the_same_reads_for_known_and_unknown_emails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Timing comes down to the work done: a wrong password must read the same
    # tables whether or not the email has an account (issue #24).
    from gotauth.storage.memory import _adapter

    calls: list[tuple[str, str]] = []
    for name in ("create", "find", "find_many", "update", "delete"):
        real = getattr(_adapter._Store, name)  # pyright: ignore[reportPrivateUsage]

        def record(
            self: Any, model: str, *args: Any, _n: str = name, _r: Any = real
        ) -> Any:
            calls.append((_n, model))
            return _r(self, model, *args)

        monkeypatch.setattr(_adapter._Store, name, record)  # pyright: ignore[reportPrivateUsage]
    app = full_app()
    async with app.client() as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        http.cookies.clear()
        seen: list[list[tuple[str, str]]] = []
        for email in ("ada@example.com", UNKNOWN):
            calls.clear()
            response = await http.post(
                "/sign-in/email", json={"email": email, "password": "wrong password"}
            )
            assert response.status_code == 401
            seen.append(list(calls))
    assert seen[0] == seen[1]
    assert ("find_many", "account") in seen[0]


def welch_t(a: list[float], b: list[float]) -> float:
    """Welch's two-sample t statistic."""
    va, vb = statistics.variance(a), statistics.variance(b)
    return (statistics.mean(a) - statistics.mean(b)) / math.sqrt(
        va / len(a) + vb / len(b)
    )


def test_welch_t_tells_equal_and_shifted_samples_apart() -> None:
    base = [1.0 + (i % 7) * 0.01 for i in range(200)]
    assert abs(welch_t(base, list(reversed(base)))) < 1
    assert welch_t([x + 0.05 for x in base], base) > 4


Body = Callable[[str, int], dict[str, Any]]  # Any: JSON


@pytest.mark.timing
@pytest.mark.parametrize(
    ("path", "body"),
    [
        pytest.param(
            "/request-password-reset",
            lambda e, _: {"email": e, "redirect_to": "/reset"},
            id="reset",
        ),
        pytest.param(
            "/send-verification-email",
            lambda e, _: {"email": e},
            id="verification",
        ),
        pytest.param(
            "/sign-in/email",
            lambda e, _: {"email": e, "password": "wrong password"},
            id="sign-in",
        ),
    ],
)
async def test_timing_does_not_reveal_accounts(path: str, body: Body) -> None:
    # Off localhost, account-only work runs after the reply (CONTRACTS 9). Welch
    # two-sample t-test over 200 runs per side, interleaved so drift hits both
    # sides alike, and alternating which goes first: the first request after
    # drain() is slower, which would otherwise always count against one side.
    # The production hash cost, not the testing kit's: this measures what a
    # deployed app does, and the hash's own jitter is part of that.
    app = full_app(
        base_url="https://auth.example.com",
        rate_limit={"enabled": False},
        advanced={"crypto": crypto_kit([TEST_SECRET])},
    )
    runs = 200
    known: list[float] = []
    unknown: list[float] = []
    async with app.client() as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        await app.auth.drain()
        for i in range(runs + 20):
            pair = [("ada@example.com", known), (UNKNOWN, unknown)]
            for email, sink in pair if i % 2 == 0 else pair[::-1]:
                start = time.perf_counter()
                await http.post(path, json=body(email, i))
                if i >= 20:  # warm-up
                    sink.append(time.perf_counter() - start)
            await app.auth.drain()
    t = welch_t(known, unknown)
    gap = (statistics.mean(known) - statistics.mean(unknown)) * 1e6
    assert abs(t) < 4.0, f"t={t:.2f}, mean gap {gap:.0f} us"
