"""TOTP, HOTP and numeric one-time codes."""

from __future__ import annotations

import base64
import hmac
import secrets
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gotauth.crypto import (
    _otp,
    crypto_kit,
    hotp,
    new_otp,
    new_totp_secret,
    totp,
    verify_totp,
)

KIT = crypto_kit("otp-tests-secret-0123456789abcdefghij")
SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 "12345678901234567890"
AT = datetime(2026, 10, 4, 12, 0, 0, tzinfo=UTC)
STEP = int(AT.timestamp()) // 30

moments = st.datetimes(
    min_value=datetime(1970, 1, 1),  # noqa: DTZ001 - bounds are naive by Hypothesis' rules
    max_value=datetime(2200, 1, 1),  # noqa: DTZ001
    timezones=st.just(UTC),
)
raw_secrets = st.binary(min_size=10, max_size=64)


@given(raw=raw_secrets, at=moments, digits=st.integers(6, 8))
def test_totp_round_trip(raw: bytes, at: datetime, digits: int) -> None:
    secret = base64.b32encode(raw).decode().rstrip("=")
    code = KIT.totp(secret, at=at, digits=digits)
    assert len(code) == digits and code.isdigit()
    step = int((at - datetime(1970, 1, 1, tzinfo=UTC)).total_seconds()) // 30
    assert KIT.verify_totp(secret, code, at=at, digits=digits) == step
    assert KIT.verify_totp(secret, code, at=at, window=0, digits=digits) == step


def test_window_accepts_neighbouring_steps_only() -> None:
    previous = KIT.totp(SECRET, at=AT - timedelta(seconds=30))
    following = KIT.totp(SECRET, at=AT + timedelta(seconds=30))
    two_back = KIT.totp(SECRET, at=AT - timedelta(seconds=60))
    assert KIT.verify_totp(SECRET, previous, at=AT) == STEP - 1
    assert KIT.verify_totp(SECRET, following, at=AT) == STEP + 1
    assert KIT.verify_totp(SECRET, previous, at=AT, window=0) is None
    assert KIT.verify_totp(SECRET, two_back, at=AT) is None
    assert KIT.verify_totp(SECRET, two_back, at=AT, window=2) == STEP - 2


def test_latest_matching_step_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    def same_code(key: bytes, counter: int, *, digits: int = 6) -> str:
        return "123456"

    monkeypatch.setattr(_otp, "hotp", same_code)
    assert verify_totp(SECRET, "123456", at=AT, window=2) == STEP + 2


def test_verify_totp_compares_every_step_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    code = KIT.totp(SECRET, at=AT - timedelta(seconds=30))
    assert KIT.verify_totp(SECRET, code, at=AT, window=1) == STEP - 1
    # No early exit: all three steps were compared.
    assert len(calls) == 3


@pytest.mark.parametrize(
    "code",
    [
        "",
        "12345",
        "1234567",
        "12345a",
        " 12345",
        "12345 ",
        "+12345",
        "-12345",
        "\u0661\u0662\u0663\u0664\u0665\u0666",  # Arabic-Indic digits
        "\uff11\uff12\uff13\uff14\uff15\uff16",  # full-width digits
    ],
)
def test_non_digit_codes_are_rejected(code: str) -> None:
    assert KIT.verify_totp(SECRET, code, at=AT) is None


def test_wrong_length_code_is_rejected_even_if_digits_match() -> None:
    eight = KIT.totp(SECRET, at=AT, digits=8)
    # The last 6 digits are the valid 6-digit code, but the 8-digit form is not.
    assert KIT.verify_totp(SECRET, eight, at=AT) is None
    assert KIT.verify_totp(SECRET, eight[-6:], at=AT) == STEP


@pytest.mark.parametrize(
    "spelling",
    [SECRET, SECRET.lower(), "GezdGNBVgy3tqojqGEZDGNBVGY3TQOJQ"],
)
def test_lower_case_and_unpadded_secrets(spelling: str) -> None:
    assert KIT.totp(spelling, at=AT) == totp(SECRET, at=AT)


def test_padded_secret() -> None:
    unpadded = base64.b32encode(b"01234567890").decode().rstrip("=")
    padded = base64.b32encode(b"01234567890").decode()
    assert unpadded != padded
    assert KIT.totp(padded, at=AT) == KIT.totp(unpadded, at=AT)


@pytest.mark.parametrize("secret", ["", "1", "A", "ABC", "AB!D", "ABCD EFGH", "====="])
def test_invalid_secret_raises(secret: str) -> None:
    with pytest.raises(ValueError, match="base32"):
        KIT.totp(secret, at=AT)
    with pytest.raises(ValueError, match="base32"):
        KIT.verify_totp(secret, "123456", at=AT)


def test_naive_or_early_datetime_raises() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        KIT.totp(SECRET, at=datetime(2026, 1, 1))  # noqa: DTZ001 - the point of the test
    with pytest.raises(ValueError, match="1970"):
        KIT.totp(SECRET, at=datetime(1969, 12, 31, tzinfo=UTC))


def test_other_time_zones_give_the_same_code() -> None:
    plus_two = AT.astimezone(timezone(timedelta(hours=2)))
    assert KIT.totp(SECRET, at=plus_two) == KIT.totp(SECRET, at=AT)


@pytest.mark.parametrize("digits", [5, 9])
def test_totp_digits_out_of_range(digits: int) -> None:
    with pytest.raises(ValueError, match="digits"):
        KIT.totp(SECRET, at=AT, digits=digits)
    with pytest.raises(ValueError, match="digits"):
        KIT.verify_totp(SECRET, "1" * digits, at=AT, digits=digits)


@pytest.mark.parametrize("window", [-1, 11])
def test_window_out_of_range(window: int) -> None:
    with pytest.raises(ValueError, match="window"):
        KIT.verify_totp(SECRET, "123456", at=AT, window=window)


def test_period_must_be_positive() -> None:
    with pytest.raises(ValueError, match="period"):
        KIT.totp(SECRET, at=AT, period=0)


def test_hotp_counter_range() -> None:
    assert len(hotp(b"key", 2**64 - 1)) == 6
    with pytest.raises(ValueError, match="counter"):
        hotp(b"key", 2**64)
    with pytest.raises(ValueError, match="counter"):
        hotp(b"key", -1)


def test_new_totp_secret() -> None:
    made = {new_totp_secret() for _ in range(200)} | {KIT.new_totp_secret()}
    assert len(made) == 201
    for secret in made:
        assert len(secret) == 32
        assert len(base64.b32decode(secret)) == 20


def test_new_otp_keeps_leading_zeros(monkeypatch: pytest.MonkeyPatch) -> None:
    def low(limit: int) -> int:
        assert limit == 10**6
        return 42

    monkeypatch.setattr(secrets, "randbelow", low)
    assert KIT.new_otp() == "000042"


@pytest.mark.parametrize("digits", range(4, 13))
def test_new_otp_format(digits: int) -> None:
    for _ in range(100):
        code = new_otp(digits)
        assert len(code) == digits
        assert code.isascii() and code.isdigit()


@pytest.mark.parametrize("digits", [0, 3, 13])
def test_new_otp_digits_out_of_range(digits: int) -> None:
    with pytest.raises(ValueError, match="digits"):
        KIT.new_otp(digits)


def test_new_otp_digits_are_uniform() -> None:
    codes = [KIT.new_otp(6) for _ in range(10_000)]
    for position in range(6):
        counts = Counter(code[position] for code in codes)
        assert set(counts) == set("0123456789")
        # Expected 1000 per digit; the standard deviation is about 30, so these
        # bounds only fail for a real bias.
        assert all(800 < count < 1200 for count in counts.values()), (position, counts)
