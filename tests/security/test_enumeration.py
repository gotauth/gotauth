"""Account enumeration (CONTRACTS 9.1): same answers, and similar timing, for known
and unknown emails."""

from __future__ import annotations

import math
import statistics
import time
from collections.abc import Callable
from typing import Any

import pytest

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


@pytest.mark.skip(
    reason="P4 (magic link, email OTP) and P5 (invitations) have not merged"
)
async def test_magic_link_otp_and_invitations() -> None:
    raise AssertionError("covered once P4 and P5 merge")


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
    # Off localhost, email goes out in the background (CONTRACTS 9), so the reply
    # does not wait for delivery. Welch two-sample t-test over 200 runs per side,
    # interleaved so drift hits both sides alike.
    app = full_app(base_url="https://auth.example.com", rate_limit={"enabled": False})
    runs = 200
    known: list[float] = []
    unknown: list[float] = []
    async with app.client() as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        await app.auth.drain()
        for i in range(runs + 20):
            for email, sink in (("ada@example.com", known), (UNKNOWN, unknown)):
                start = time.perf_counter()
                await http.post(path, json=body(email, i))
                if i >= 20:  # warm-up
                    sink.append(time.perf_counter() - start)
            await app.auth.drain()
    t = welch_t(known, unknown)
    gap = (statistics.mean(known) - statistics.mean(unknown)) * 1e6
    assert abs(t) < 4.0, f"t={t:.2f}, mean gap {gap:.0f} us"
