"""Key derivation, signing and authenticated encryption primitives.

The kit in ``_kit.py`` picks the keys; the functions here only apply them, so the spec
vectors can test each step on its own.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from gotauth.crypto._encoding import b64url_decode, b64url_encode

__all__ = [
    "CIPHERTEXT_VERSION",
    "GCM_TAG_BYTES",
    "HKDF_MAX_LENGTH",
    "NONCE_BYTES",
    "Secret",
    "check_purpose",
    "decrypt_with_key",
    "encrypt_with_key",
    "hkdf_sha256",
    "parse_ciphertext",
    "purpose_info",
    "signature",
]

HKDF_MAX_LENGTH = 255 * 32
"""Longest HKDF-SHA256 output (RFC 5869 section 2.3)."""

NONCE_BYTES = 12
"""AES-GCM nonce size: the 96 bits NIST SP 800-38D recommends for random nonces."""

GCM_TAG_BYTES = 16
CIPHERTEXT_VERSION = "v1"
_INFO_PREFIX = b"gotauth:"


class Secret:
    """Holds key material and keeps it out of ``repr()``, logs and tracebacks.

    Error reporters that print local variables or object attributes see
    ``<redacted>`` instead of the bytes.
    """

    __slots__ = ("_value",)

    def __init__(self, value: bytes) -> None:
        """Wrap key material.

        Args:
            value: The raw bytes.
        """
        self._value = value

    def reveal(self) -> bytes:
        """Return the raw bytes. Use them inline; don't keep them in a variable.

        Returns:
            The wrapped bytes.
        """
        return self._value

    def __repr__(self) -> str:
        """Return a placeholder instead of the key material."""
        return "<redacted>"


def check_purpose(purpose: str) -> None:
    """Reject an empty purpose string, which is always a caller bug.

    Args:
        purpose: The purpose to check.

    Raises:
        ValueError: If ``purpose`` is empty.
    """
    if not purpose:
        msg = "purpose must not be empty"
        raise ValueError(msg)


def purpose_info(purpose: str) -> bytes:
    """Return the HKDF ``info`` for a purpose: ``b"gotauth:"`` plus its UTF-8 bytes.

    Args:
        purpose: The purpose, for example ``"sign:challenge"`` or ``"encrypt"``.

    Returns:
        The info bytes.
    """
    return _INFO_PREFIX + purpose.encode("utf-8")


def hkdf_sha256(
    ikm: bytes, *, info: bytes, length: int = 32, salt: bytes | None = None
) -> bytes:
    """Derive key material with HKDF-SHA256 (RFC 5869).

    Args:
        ikm: Input keying material.
        info: Context and application specific information.
        length: Output length in bytes, 1 to 8160.
        salt: Optional salt. None and ``b""`` both mean 32 zero bytes (RFC 5869
            section 2.2).

    Returns:
        ``length`` bytes of output keying material.

    Raises:
        ValueError: If ``length`` is out of range.
    """
    if not 1 <= length <= HKDF_MAX_LENGTH:
        msg = f"length must be between 1 and {HKDF_MAX_LENGTH}"
        raise ValueError(msg)
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        ikm
    )


def signature(key: Secret, value: str) -> str:
    """Return the unpadded base64url HMAC-SHA256 of ``value`` under ``key``.

    Args:
        key: The signing key.
        value: The text to sign, as UTF-8.

    Returns:
        43 base64url characters.
    """
    mac = hmac.new(key.reveal(), value.encode("utf-8"), hashlib.sha256)
    return b64url_encode(mac.digest())


def encrypt_with_key(key: Secret, nonce: bytes, plaintext: str, purpose: str) -> str:
    """Encrypt with AES-256-GCM using a given nonce.

    The kit always passes a fresh random nonce. Taking it as an argument lets the
    spec vectors pin the output.

    Args:
        key: The 32-byte encryption key.
        nonce: A 12-byte nonce, never reused with the same key.
        plaintext: The text to encrypt, as UTF-8.
        purpose: Bound to the ciphertext as associated data.

    Returns:
        ``"v1.<b64url nonce>.<b64url ciphertext and tag>"``.
    """
    body = AESGCM(key.reveal()).encrypt(
        nonce, plaintext.encode("utf-8"), purpose.encode("utf-8")
    )
    return f"{CIPHERTEXT_VERSION}.{b64url_encode(nonce)}.{b64url_encode(body)}"


def parse_ciphertext(ciphertext: str) -> tuple[bytes, bytes] | None:
    """Split a ``v1`` ciphertext into nonce and body.

    Args:
        ciphertext: The text made by `encrypt_with_key`.

    Returns:
        ``(nonce, ciphertext and tag)``, or None if the format is wrong.
    """
    parts = ciphertext.split(".")
    if len(parts) != 3 or parts[0] != CIPHERTEXT_VERSION:
        return None
    try:
        nonce = b64url_decode(parts[1])
        body = b64url_decode(parts[2])
    except ValueError:
        return None
    if len(nonce) != NONCE_BYTES or len(body) < GCM_TAG_BYTES:
        return None
    return nonce, body


def decrypt_with_key(
    key: Secret, nonce: bytes, body: bytes, purpose: str
) -> str | None:
    """Decrypt and authenticate one ciphertext body with one key.

    Args:
        key: The 32-byte encryption key.
        nonce: The 12-byte nonce.
        body: Ciphertext followed by the 16-byte tag.
        purpose: The associated data the ciphertext must have been made with.

    Returns:
        The plaintext, or None if the key, purpose or bytes don't match.
    """
    try:
        raw = AESGCM(key.reveal()).decrypt(nonce, body, purpose.encode("utf-8"))
    except InvalidTag:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
