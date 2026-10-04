"""CONTRACTS section 8: the crypto kit interface (implemented by ``gotauth.crypto``)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Protocol, runtime_checkable

__all__ = ["CRYPTO_PURPOSES", "CryptoKit", "PasswordCheck"]

CRYPTO_PURPOSES: Mapping[str, str] = MappingProxyType(
    {
        "session_data": "C3",
        "challenge": "C1",
        "oauth_state": "C4",
        "account_token": "C4",
        "two_factor_secret": "P2",
        "trusted_device": "P2",
        "passkey_challenge": "P3",
        "jwk_private": "O1",
        "oauth_consent": "O1",
    }
)
"""Purpose strings in use -> owning work package (section 8). ``account_token`` is also
used by I1. Reusing another work package's purpose is a bug."""


@dataclass(frozen=True)
class PasswordCheck:
    """The result of ``verify_password``.

    Attributes:
        ok: The password matches.
        needs_rehash: The algorithm or parameters differ from the configured default.
    """

    ok: bool
    needs_rehash: bool


@runtime_checkable
class CryptoKit(Protocol):
    """Every cryptographic operation GotAuth uses."""

    def random_token(self, prefix: str = "", nbytes: int = 32) -> str:
        """Return ``prefix`` + base64url (no padding) of ``nbytes`` random bytes."""
        ...

    def hash_token(self, token: str) -> str:
        """Return the SHA-256 hex digest of the token's UTF-8 bytes."""
        ...

    def equal(self, a: str | bytes, b: str | bytes) -> bool:
        """Compare in constant time (``hmac.compare_digest``)."""
        ...

    async def hash_password(self, password: str) -> str:
        """Hash a password with the configured algorithm, in a worker thread."""
        ...

    async def verify_password(self, password: str, stored: str) -> PasswordCheck:
        """Check a password; runs a dummy hash when ``stored`` is empty."""
        ...

    def sign(self, value: str, *, purpose: str) -> str:
        """Return ``"<value>.<b64url HMAC-SHA256>"`` signed with the current secret."""
        ...

    def unsign(self, signed: str, *, purpose: str) -> str | None:
        """Return the value if any configured secret verifies it, else ``None``."""
        ...

    def encrypt(self, plaintext: str, *, purpose: str) -> str:
        """Encrypt with AES-256-GCM: ``"v1.<b64 nonce>.<b64 ciphertext>"``."""
        ...

    def decrypt(self, ciphertext: str, *, purpose: str) -> str | None:
        """Decrypt, or return ``None`` on tampering, a wrong purpose or a bad format."""
        ...

    def derive_key(self, purpose: str, length: int = 32) -> bytes:
        """HKDF-SHA256 of the current secret with ``info=b"gotauth:" + purpose``."""
        ...

    def new_totp_secret(self) -> str:
        """Return 20 random bytes as base32 without padding."""
        ...

    def totp(
        self, secret_b32: str, *, at: datetime, digits: int = 6, period: int = 30
    ) -> str:
        """Return the RFC 6238 code at ``at``."""
        ...

    def verify_totp(
        self, secret_b32: str, code: str, *, at: datetime, window: int = 1
    ) -> int | None:
        """Return the matched time step, or ``None``; callers reject a reused step."""
        ...

    def new_otp(self, digits: int = 6) -> str:
        """Return a uniform random numeric code."""
        ...

    def pkce_s256(self, verifier: str) -> str:
        """Return the RFC 7636 S256 challenge of a verifier."""
        ...

    def new_ulid(self, at: datetime) -> str:
        """Return a 26-character ULID, monotonic within one millisecond."""
        ...
