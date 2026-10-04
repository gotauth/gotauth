"""Random tokens, token hashing, constant-time comparison and PKCE."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from gotauth.crypto._encoding import b64url_encode

__all__ = [
    "MIN_TOKEN_BYTES",
    "encode_token",
    "equal",
    "hash_token",
    "pkce_s256",
    "random_token",
]

MIN_TOKEN_BYTES = 16
"""Fewest random bytes `random_token` accepts (128 bits): no guessable tokens."""

# RFC 7636 section 4.1: 43 to 128 characters from the unreserved set.
_PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")


def random_token(prefix: str = "", nbytes: int = 32) -> str:
    """Make a random token: ``prefix`` plus base64url of ``nbytes`` random bytes.

    Args:
        prefix: Text put in front, for example ``"gas_"`` (CONTRACTS section 7).
        nbytes: Number of random bytes. 32 bytes give a 43-character body.

    Returns:
        The token. Store only `hash_token` of it.

    Raises:
        ValueError: If ``nbytes`` is below `MIN_TOKEN_BYTES`.
    """
    if nbytes < MIN_TOKEN_BYTES:
        msg = f"nbytes must be at least {MIN_TOKEN_BYTES}"
        raise ValueError(msg)
    return encode_token(prefix, secrets.token_bytes(nbytes))


def encode_token(prefix: str, raw: bytes) -> str:
    """Format given random bytes as a token, the deterministic half of `random_token`.

    Args:
        prefix: Text put in front.
        raw: The random bytes.

    Returns:
        ``prefix`` plus unpadded base64url of ``raw``.
    """
    return prefix + b64url_encode(raw)


def hash_token(token: str) -> str:
    """Hash a token for storage: SHA-256 of its UTF-8 bytes, as lower-case hex.

    Args:
        token: The raw token or, for short codes, ``identifier + ":" + code``.

    Returns:
        64 hex characters.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def equal(a: str | bytes, b: str | bytes) -> bool:
    """Compare two secrets in constant time.

    Text is compared as UTF-8 bytes, so a ``str`` and the same ``bytes`` are equal.

    Args:
        a: The first value.
        b: The second value.

    Returns:
        True if both values have the same bytes. The time taken depends only on the
        lengths, not on where the values differ.
    """
    return hmac.compare_digest(_as_bytes(a), _as_bytes(b))


def _as_bytes(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def pkce_s256(verifier: str) -> str:
    """Compute the PKCE S256 code challenge of a verifier (RFC 7636 section 4.2).

    Args:
        verifier: The code verifier: 43 to 128 characters from ``A-Z a-z 0-9 - . _ ~``.

    Returns:
        Unpadded base64url of SHA-256 over the verifier's ASCII bytes.

    Raises:
        ValueError: If the verifier breaks the RFC 7636 section 4.1 rules.
    """
    if _PKCE_VERIFIER.fullmatch(verifier) is None:
        msg = "PKCE code verifier must be 43 to 128 unreserved characters (RFC 7636)"
        raise ValueError(msg)
    return b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
