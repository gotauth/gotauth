"""HOTP (RFC 4226), TOTP (RFC 6238) and numeric one-time codes."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime

from gotauth.crypto._encoding import b32_decode_lenient, b32_encode, unix_seconds
from gotauth.crypto._tokens import equal

__all__ = [
    "MAX_TOTP_WINDOW",
    "OTP_DIGITS_RANGE",
    "TOTP_DIGITS_RANGE",
    "TOTP_SECRET_BYTES",
    "hotp",
    "new_otp",
    "new_totp_secret",
    "totp",
    "verify_totp",
]

TOTP_SECRET_BYTES = 20
"""Size of a new TOTP secret: 160 bits, the length RFC 4226 section 4 recommends."""

TOTP_DIGITS_RANGE = range(6, 9)
"""Allowed HOTP and TOTP code lengths (RFC 4226 section 5.3: at least 6, up to 8)."""

OTP_DIGITS_RANGE = range(4, 13)
"""Allowed `new_otp` code lengths."""

MAX_TOTP_WINDOW = 10
"""Largest `verify_totp` window, so a bad argument cannot make it loop for long."""


def _check_digits(digits: int) -> None:
    if digits not in TOTP_DIGITS_RANGE:
        msg = "digits must be 6, 7 or 8"
        raise ValueError(msg)


def _check_period(period: int) -> None:
    if period < 1:
        msg = "period must be at least 1 second"
        raise ValueError(msg)


def hotp(key: bytes, counter: int, *, digits: int = 6) -> str:
    """Compute an HOTP code (RFC 4226 section 5.3) with HMAC-SHA-1.

    Args:
        key: The shared secret as raw bytes.
        counter: The moving factor, 0 to 2**64 - 1.
        digits: Code length, 6 to 8.

    Returns:
        The code as ``digits`` ASCII digits, leading zeros kept.

    Raises:
        ValueError: If ``counter`` or ``digits`` is out of range.
    """
    if not 0 <= counter < 1 << 64:
        msg = "counter must fit in 8 unsigned bytes"
        raise ValueError(msg)
    _check_digits(digits)
    mac = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def new_totp_secret() -> str:
    """Make a new TOTP secret.

    Returns:
        20 random bytes as upper-case base32 without padding (32 characters).
    """
    return b32_encode(secrets.token_bytes(TOTP_SECRET_BYTES))


def totp(secret_b32: str, *, at: datetime, digits: int = 6, period: int = 30) -> str:
    """Compute the TOTP code for a moment (RFC 6238, HMAC-SHA-1).

    Args:
        secret_b32: The shared secret in base32; lower case and missing padding are
            accepted.
        at: The moment, timezone-aware and not before 1970.
        digits: Code length, 6 to 8.
        period: Time step in seconds.

    Returns:
        The code as ``digits`` ASCII digits.

    Raises:
        ValueError: If the secret is not base32, ``at`` is naive or before 1970, or
            ``digits`` or ``period`` is out of range.
    """
    _check_period(period)
    key = b32_decode_lenient(secret_b32)
    return hotp(key, unix_seconds(at) // period, digits=digits)


def verify_totp(
    secret_b32: str,
    code: str,
    *,
    at: datetime,
    window: int = 1,
    digits: int = 6,
    period: int = 30,
) -> int | None:
    """Check a TOTP code against the time steps around ``at``.

    Every step from ``window`` steps before to ``window`` steps after the current
    one is compared in constant time, without stopping at the first match, so the
    time taken does not reveal which step matched.

    Args:
        secret_b32: The shared secret in base32; lower case and missing padding are
            accepted.
        code: The code the user typed. Anything but exactly ``digits`` ASCII digits
            is rejected.
        at: The moment to check against, timezone-aware.
        window: How many steps before and after the current one to accept, 0 to 10.
        digits: Code length, 6 to 8. Must match the length used at enrollment.
        period: Time step in seconds.

    Returns:
        The matched time step (seconds since 1970 divided by ``period``), so the
        caller can reject a second use of the same or an earlier step. If several
        steps match, the latest one. None if no step matches.

    Raises:
        ValueError: If the stored secret is not base32, ``at`` is naive or before
            1970, or ``window``, ``digits`` or ``period`` is out of range.
    """
    if not 0 <= window <= MAX_TOTP_WINDOW:
        msg = f"window must be between 0 and {MAX_TOTP_WINDOW}"
        raise ValueError(msg)
    _check_digits(digits)
    _check_period(period)
    key = b32_decode_lenient(secret_b32)
    current = unix_seconds(at) // period
    if len(code) != digits or not (code.isascii() and code.isdigit()):
        return None
    matched: int | None = None
    for step in range(max(0, current - window), current + window + 1):
        if equal(hotp(key, step, digits=digits), code):
            matched = step
    return matched


def new_otp(digits: int = 6) -> str:
    """Make a uniformly random numeric one-time code.

    ``secrets.randbelow`` draws from exactly ``10**digits`` values, so there is no
    modulo bias. Callers store ``hash_token(identifier + ":" + code)`` (CONTRACTS 2.1).

    Args:
        digits: Code length, 4 to 12.

    Returns:
        ``digits`` ASCII digits, leading zeros kept.

    Raises:
        ValueError: If ``digits`` is out of range.
    """
    if digits not in OTP_DIGITS_RANGE:
        msg = "digits must be between 4 and 12"
        raise ValueError(msg)
    return str(secrets.randbelow(10**digits)).zfill(digits)
