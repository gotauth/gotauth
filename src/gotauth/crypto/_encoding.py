"""Strict text encodings shared by the crypto kit.

Base64 decoding here is strict on purpose: only the unpadded, canonical encoding of a
value is accepted. A lenient decoder would accept several spellings of the same
signature or ciphertext, which makes values malleable and lets ports disagree.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

__all__ = [
    "b32_decode_lenient",
    "b32_encode",
    "b64_decode",
    "b64_encode",
    "b64url_decode",
    "b64url_encode",
    "crockford_encode",
    "unix_millis",
    "unix_seconds",
]

_B64URL_CHARS = re.compile(r"[A-Za-z0-9_-]*")
_B64_CHARS = re.compile(r"[A-Za-z0-9+/]*")
_B32_CHARS = re.compile(r"[A-Za-z2-7]+")
# Unpadded base32 lengths that cannot occur (RFC 4648 section 6).
_B32_BAD_LENGTHS = frozenset({1, 3, 6})
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url (RFC 4648 section 5) without padding.

    Args:
        data: The bytes to encode.

    Returns:
        The ASCII text, for example 43 characters for 32 bytes.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded, canonical base64url.

    Args:
        text: The encoded text.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If the text has padding, characters outside the base64url
            alphabet, an impossible length, or non-zero trailing bits.
    """
    return _strict_decode(text, _B64URL_CHARS, base64.urlsafe_b64decode, b64url_encode)


def b64_encode(data: bytes) -> str:
    """Encode bytes as standard base64 (RFC 4648 section 4) without padding.

    Args:
        data: The bytes to encode.

    Returns:
        The ASCII text.
    """
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode(text: str) -> bytes:
    """Decode unpadded, canonical standard base64.

    Args:
        text: The encoded text.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If the text is not the canonical unpadded encoding of some bytes.
    """
    return _strict_decode(text, _B64_CHARS, base64.b64decode, b64_encode)


def _strict_decode(
    text: str,
    alphabet: re.Pattern[str],
    decode: Callable[[str], bytes],
    encode: Callable[[bytes], str],
) -> bytes:
    if alphabet.fullmatch(text) is None or len(text) % 4 == 1:
        msg = "invalid base64 text"
        raise ValueError(msg)
    try:
        raw = decode(text + "=" * (-len(text) % 4))
    except binascii.Error as exc:
        msg = "invalid base64 text"
        raise ValueError(msg) from exc
    if encode(raw) != text:
        msg = "non-canonical base64 text"
        raise ValueError(msg)
    return raw


def b32_encode(data: bytes) -> str:
    """Encode bytes as upper-case base32 (RFC 4648 section 6) without padding.

    Args:
        data: The bytes to encode.

    Returns:
        The ASCII text, for example 32 characters for 20 bytes.
    """
    return base64.b32encode(data).rstrip(b"=").decode("ascii")


def b32_decode_lenient(text: str) -> bytes:
    """Decode a base32 TOTP secret, accepting lower case and missing padding.

    Authenticator apps and other libraries write secrets in either case and often
    without padding, so both are accepted here. Nothing else is.

    Args:
        text: The base32 text.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If the text is empty or not base32.
    """
    body = text.rstrip("=")
    if _B32_CHARS.fullmatch(body) is None or len(body) % 8 in _B32_BAD_LENGTHS:
        msg = "invalid base32 secret"
        raise ValueError(msg)
    try:
        return base64.b32decode(body.upper() + "=" * (-len(body) % 8))
    except binascii.Error as exc:
        msg = "invalid base32 secret"
        raise ValueError(msg) from exc


def crockford_encode(value: int, length: int) -> str:
    """Encode a non-negative integer as fixed-length Crockford base32.

    Args:
        value: The integer to encode.
        length: The number of output characters (5 bits each).

    Returns:
        Upper-case text of exactly ``length`` characters.

    Raises:
        ValueError: If ``value`` is negative or does not fit.
    """
    if value < 0 or value >= 1 << (5 * length):
        msg = "value does not fit the requested length"
        raise ValueError(msg)
    chars = [
        _CROCKFORD[(value >> shift) & 31] for shift in range(5 * (length - 1), -1, -5)
    ]
    return "".join(chars)


def _since_epoch(at: datetime) -> timedelta:
    if at.tzinfo is None or at.utcoffset() is None:
        # A naive datetime would be read as local time and give a wrong time step.
        msg = "datetime must be timezone-aware"
        raise ValueError(msg)
    delta = at - _EPOCH
    if delta < timedelta(0):
        msg = "datetime must not be before 1970-01-01T00:00:00Z"
        raise ValueError(msg)
    return delta


def unix_seconds(at: datetime) -> int:
    """Return whole seconds since the Unix epoch, rounded down.

    Args:
        at: A timezone-aware datetime, not before 1970.

    Returns:
        The number of seconds.

    Raises:
        ValueError: If ``at`` is naive or before the epoch.
    """
    return _since_epoch(at) // timedelta(seconds=1)


def unix_millis(at: datetime) -> int:
    """Return whole milliseconds since the Unix epoch, rounded down.

    Args:
        at: A timezone-aware datetime, not before 1970.

    Returns:
        The number of milliseconds.

    Raises:
        ValueError: If ``at`` is naive or before the epoch.
    """
    return _since_epoch(at) // timedelta(milliseconds=1)
