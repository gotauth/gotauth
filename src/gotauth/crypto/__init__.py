"""Crypto kit: token hashing, password hashing, signing, encryption and one-time codes.

Endpoint code uses the kit on its context (``ctx.crypto``). Code without a context
builds one with `crypto_kit`::

    from gotauth.crypto import crypto_kit

    kit = crypto_kit(["current-secret-of-32-characters-or-more", "previous-secret-..."])
    token = kit.random_token("gas_")
    cookie = kit.sign("value", purpose="challenge")

The functions that need no secret (`random_token`, `hash_token`, `equal`, `pkce_s256`,
`new_ulid`, `new_otp`, `new_totp_secret`, `totp`, `verify_totp`) are also available
at module level, for code such as id generators and CLI commands. `hotp` and
`hkdf_sha256` are the primitives behind TOTP and `derive_key`, exported for the spec
vectors.
"""

from __future__ import annotations

from gotauth.crypto._errors import ConfigError
from gotauth.crypto._keys import hkdf_sha256
from gotauth.crypto._kit import MIN_SECRET_LENGTH, DefaultCryptoKit, crypto_kit
from gotauth.crypto._otp import hotp, new_otp, new_totp_secret, totp, verify_totp
from gotauth.crypto._passwords import (
    DEFAULT_SCRYPT,
    PasswordAlgorithm,
    PasswordCheck,
    ScryptParams,
)
from gotauth.crypto._tokens import equal, hash_token, pkce_s256, random_token
from gotauth.crypto._ulid import new_ulid

__all__ = [
    "DEFAULT_SCRYPT",
    "MIN_SECRET_LENGTH",
    "ConfigError",
    "DefaultCryptoKit",
    "PasswordAlgorithm",
    "PasswordCheck",
    "ScryptParams",
    "crypto_kit",
    "equal",
    "hash_token",
    "hkdf_sha256",
    "hotp",
    "new_otp",
    "new_totp_secret",
    "new_ulid",
    "pkce_s256",
    "random_token",
    "totp",
    "verify_totp",
]
