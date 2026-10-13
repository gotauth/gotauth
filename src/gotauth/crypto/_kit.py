"""The crypto kit: the one object every module uses for cryptography (CONTRACTS 8)."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Sequence
from datetime import datetime

from gotauth.crypto import _otp, _tokens, _ulid
from gotauth.crypto._errors import ConfigError
from gotauth.crypto._keys import (
    NONCE_BYTES,
    Secret,
    check_purpose,
    decrypt_with_key,
    encrypt_with_key,
    hkdf_sha256,
    parse_ciphertext,
    purpose_info,
    signature,
)
from gotauth.crypto._passwords import (
    DEFAULT_SCRYPT,
    PasswordAlgorithm,
    PasswordCheck,
    PasswordHasher,
    ScryptParams,
)

__all__ = ["MIN_SECRET_LENGTH", "DefaultCryptoKit", "crypto_kit"]

MIN_SECRET_LENGTH = 32
"""Fewest characters a secret may have (CONTRACTS section 8)."""

_SIGN_PREFIX = "sign:"
_ENCRYPT_PURPOSE = "encrypt"
# Purposes come from code, not from requests, so the cache stays small. The bound
# only guards against a caller that builds purposes from data.
_KEY_CACHE_LIMIT = 1024


def _load_secrets(secret: str | Sequence[str]) -> tuple[Secret, ...]:
    # Typed as object: callers outside pyright may pass bytes or None in the list.
    values: list[object] = [secret] if isinstance(secret, str) else [*secret]
    if not values:
        msg = "secret must be a string or a non-empty list of strings"
        raise ConfigError(msg)
    loaded: list[Secret] = []
    for position, value in enumerate(values, start=1):
        if not isinstance(value, str):
            msg = f"secret {position} must be a string"
            raise ConfigError(msg)
        if len(value) < MIN_SECRET_LENGTH:
            # Never put the value or a part of it in the message.
            msg = f"secret {position} must have at least {MIN_SECRET_LENGTH} characters"
            raise ConfigError(msg)
        try:
            loaded.append(Secret(value.encode("utf-8")))
        except UnicodeEncodeError:
            # "from None": the codec's message would quote part of the secret.
            msg = f"secret {position} is not valid Unicode"
            raise ConfigError(msg) from None
    return tuple(loaded)


class DefaultCryptoKit:
    """GotAuth's implementation of the ``CryptoKit`` protocol (CONTRACTS section 8).

    Build it with `crypto_kit`. The first secret signs, encrypts and derives keys;
    `unsign` and `decrypt` accept every configured secret, so a secret can be
    rotated by putting the new one first and keeping the old one until its signed
    and encrypted values have expired.
    """

    __slots__ = ("_key_cache", "_passwords", "_secrets")

    def __init__(
        self,
        secret: str | Sequence[str],
        *,
        password_algorithm: PasswordAlgorithm = "scrypt",  # noqa: S107 - a name, not a password
        scrypt_params: ScryptParams | None = None,
    ) -> None:
        """Create a kit. Prefer `crypto_kit`, which has the same arguments.

        Args:
            secret: A secret of at least 32 characters, or a list
                ``[current, *previous]`` for rotation.
            password_algorithm: The algorithm for new password hashes.

        Raises:
            ConfigError: If a secret is too short or not a string, the list is empty,
                or the password algorithm is unknown or its extra is missing.
        """
        self._secrets = _load_secrets(secret)
        self._passwords = PasswordHasher(
            password_algorithm,
            scrypt=scrypt_params if scrypt_params is not None else DEFAULT_SCRYPT,
        )
        self._key_cache: dict[tuple[int, str, int], Secret] = {}

    def __repr__(self) -> str:
        """Describe the kit without its secrets."""
        return (
            f"DefaultCryptoKit(secrets=<{len(self._secrets)} redacted>, "
            f"password_algorithm={self._passwords.algorithm!r})"
        )

    @property
    def password_algorithm(self) -> PasswordAlgorithm:
        """The algorithm used for new password hashes."""
        return self._passwords.algorithm

    def _key(self, index: int, purpose: str, length: int = 32) -> Secret:
        cache_key = (index, purpose, length)
        key = self._key_cache.get(cache_key)
        if key is None:
            check_purpose(purpose)
            key = Secret(
                hkdf_sha256(
                    self._secrets[index].reveal(),
                    info=purpose_info(purpose),
                    length=length,
                )
            )
            if len(self._key_cache) >= _KEY_CACHE_LIMIT:
                self._key_cache.clear()
            self._key_cache[cache_key] = key
        return key

    def random_token(self, prefix: str = "", nbytes: int = 32) -> str:
        """Make a random token: ``prefix`` plus base64url of ``nbytes`` random bytes.

        Args:
            prefix: Text put in front, for example ``"gas_"`` (CONTRACTS section 7).
            nbytes: Number of random bytes, at least 16. 32 bytes give 43 characters.

        Returns:
            The token. Store only `hash_token` of it.
        """
        return _tokens.random_token(prefix, nbytes)

    def hash_token(self, token: str) -> str:
        """Hash a token for storage: SHA-256 of its UTF-8 bytes, as lower-case hex.

        Args:
            token: The raw token or, for short codes, ``identifier + ":" + code``.

        Returns:
            64 hex characters.
        """
        return _tokens.hash_token(token)

    def equal(self, a: str | bytes, b: str | bytes) -> bool:
        """Compare two secrets in constant time (``hmac.compare_digest`` on bytes).

        Args:
            a: The first value; text is compared as UTF-8.
            b: The second value.

        Returns:
            True if both have the same bytes.
        """
        return _tokens.equal(a, b)

    async def hash_password(self, password: str) -> str:
        """Hash a password in a worker thread, so the event loop keeps running.

        Args:
            password: The password.

        Returns:
            The tagged stored form, for example ``scrypt$ln=15,r=8,p=3$<salt>$<hash>``.

        Raises:
            ValueError: If the password cannot be encoded as UTF-8.
        """
        return await asyncio.to_thread(self._passwords.hash, password)

    async def verify_password(self, password: str, stored: str) -> PasswordCheck:
        """Verify a password in a worker thread.

        Pass ``stored=""`` for an unknown user: the kit then runs a full hash with
        the configured algorithm and returns ``ok=False``, so the response time does
        not reveal whether the account exists. Unknown tags and malformed hashes are
        handled the same way.

        Args:
            password: The password the user sent.
            stored: The stored hash, or ``""``.

        Returns:
            ``ok`` and ``needs_rehash`` (True only when ``ok`` is True and the hash
            uses another algorithm or other parameters than the configured default).

        Raises:
            ConfigError: If ``stored`` is an argon2id or bcrypt hash and the extra
                that verifies it is not installed.
        """
        return await asyncio.to_thread(self._passwords.verify, password, stored)

    def sign(self, value: str, *, purpose: str) -> str:
        """Sign a value with the current secret.

        Args:
            value: The text to sign. It may contain dots.
            purpose: What the value is for (see the CONTRACTS section 8 registry).
                A value signed for one purpose never verifies for another.

        Returns:
            ``"<value>.<b64url HMAC-SHA256>"``, keyed with
            ``derive_key("sign:" + purpose)``.

        Raises:
            ValueError: If ``purpose`` is empty.
        """
        check_purpose(purpose)
        return f"{value}.{signature(self._key(0, _SIGN_PREFIX + purpose), value)}"

    def unsign(self, signed: str, *, purpose: str) -> str | None:
        """Check a signed value against every configured secret.

        Args:
            signed: The text made by `sign`.
            purpose: The purpose it must have been signed for.

        Returns:
            The original value, or None if the signature is missing, malformed, made
            for another purpose or made with a secret that is no longer configured.

        Raises:
            ValueError: If ``purpose`` is empty.
        """
        check_purpose(purpose)
        value, separator, given = signed.rpartition(".")
        if not _utf8(value):
            # `sign` cannot have produced it: lone surrogates do not encode as UTF-8.
            return None
        valid = False
        # Check every secret without stopping early, so the time taken does not
        # depend on which one matched.
        for index in range(len(self._secrets)):
            expected = signature(self._key(index, _SIGN_PREFIX + purpose), value)
            valid |= _tokens.equal(expected, given)
        return value if valid and separator else None

    def encrypt(self, plaintext: str, *, purpose: str) -> str:
        """Encrypt text with AES-256-GCM under the current secret.

        Args:
            plaintext: The text to encrypt.
            purpose: Bound to the ciphertext as associated data; decryption with
                another purpose fails.

        Returns:
            ``"v1.<b64url nonce>.<b64url ciphertext and tag>"`` with a random 12-byte
            nonce, keyed with ``derive_key("encrypt")``.

        Raises:
            ValueError: If ``purpose`` is empty.
        """
        check_purpose(purpose)
        nonce = secrets.token_bytes(NONCE_BYTES)
        return encrypt_with_key(
            self._key(0, _ENCRYPT_PURPOSE), nonce, plaintext, purpose
        )

    def decrypt(self, ciphertext: str, *, purpose: str) -> str | None:
        """Decrypt text made by `encrypt`, trying every configured secret.

        Args:
            ciphertext: The text made by `encrypt`.
            purpose: The purpose it must have been encrypted for.

        Returns:
            The plaintext, or None if the text is malformed, truncated, tampered
            with, encrypted for another purpose or under a secret that is no longer
            configured.

        Raises:
            ValueError: If ``purpose`` is empty.
        """
        check_purpose(purpose)
        parsed = parse_ciphertext(ciphertext)
        if parsed is None:
            return None
        nonce, body = parsed
        for index in range(len(self._secrets)):
            plaintext = decrypt_with_key(
                self._key(index, _ENCRYPT_PURPOSE), nonce, body, purpose
            )
            if plaintext is not None:
                return plaintext
        return None

    def derive_key(self, purpose: str, length: int = 32) -> bytes:
        """Derive a key from the current secret with HKDF-SHA256.

        Args:
            purpose: Becomes ``info = b"gotauth:" + purpose``; the salt is empty.
            length: Key length in bytes, 1 to 8160.

        Returns:
            The key bytes.

        Raises:
            ValueError: If ``purpose`` is empty or ``length`` is out of range.
        """
        return self._key(0, purpose, length).reveal()

    def new_totp_secret(self) -> str:
        """Make a new TOTP secret: 20 random bytes, base32 without padding.

        Returns:
            32 upper-case base32 characters.
        """
        return _otp.new_totp_secret()

    def totp(
        self, secret_b32: str, *, at: datetime, digits: int = 6, period: int = 30
    ) -> str:
        """Compute the TOTP code for a moment (RFC 6238, HMAC-SHA-1).

        Args:
            secret_b32: The secret in base32; lower case and missing padding are fine.
            at: The moment, timezone-aware.
            digits: Code length, 6 to 8.
            period: Time step in seconds.

        Returns:
            The code, leading zeros kept.
        """
        return _otp.totp(secret_b32, at=at, digits=digits, period=period)

    def verify_totp(
        self,
        secret_b32: str,
        code: str,
        *,
        at: datetime,
        window: int = 1,
        digits: int = 6,
        period: int = 30,
    ) -> int | None:
        """Check a TOTP code against the steps from ``window`` before to after ``at``.

        Args:
            secret_b32: The secret in base32; lower case and missing padding are fine.
            code: The code the user typed; anything but ``digits`` ASCII digits fails.
            at: The moment, timezone-aware.
            window: Steps accepted on each side of the current one, 0 to 10.
            digits: Code length used at enrollment, 6 to 8.
            period: Time step in seconds.

        Returns:
            The matched time step (the latest if several match), so callers can
            reject reuse of the same step; None if the code does not match.
        """
        return _otp.verify_totp(
            secret_b32, code, at=at, window=window, digits=digits, period=period
        )

    def new_otp(self, digits: int = 6) -> str:
        """Make a uniformly random numeric one-time code.

        Args:
            digits: Code length, 4 to 12.

        Returns:
            ``digits`` ASCII digits, leading zeros kept.
        """
        return _otp.new_otp(digits)

    def pkce_s256(self, verifier: str) -> str:
        """Compute the PKCE S256 code challenge (RFC 7636).

        Args:
            verifier: 43 to 128 characters from ``A-Z a-z 0-9 - . _ ~``.

        Returns:
            Unpadded base64url of SHA-256 over the verifier.

        Raises:
            ValueError: If the verifier breaks the RFC 7636 rules.
        """
        return _tokens.pkce_s256(verifier)

    def new_ulid(self, at: datetime) -> str:
        """Make a ULID, strictly increasing within one millisecond in this process.

        Args:
            at: The moment, timezone-aware.

        Returns:
            26 upper-case Crockford base32 characters.
        """
        return _ulid.new_ulid(at)


def crypto_kit(
    secret: str | Sequence[str],
    *,
    password_algorithm: PasswordAlgorithm = "scrypt",  # noqa: S107 - a name, not a password
    scrypt_params: ScryptParams | None = None,
) -> DefaultCryptoKit:
    """Build the crypto kit (CONTRACTS 13.2).

    Args:
        secret: A secret of at least 32 characters, or a list ``[current, *previous]``
            for rotation. The first one signs and encrypts; all of them verify.
        password_algorithm: ``"scrypt"`` (default, standard library) or ``"argon2id"``
            (needs the ``argon2`` extra).
        scrypt_params: Parameters for new scrypt hashes; the default is the OWASP
            minimum (``DEFAULT_SCRYPT``). Lower them only in tests: the testing kit
            uses ``TEST_SCRYPT``.

    Returns:
        A kit that implements the ``CryptoKit`` protocol.

    Raises:
        ConfigError: If a secret is shorter than 32 characters, the list is empty, or
            the password algorithm is unknown or its extra is not installed.
    """
    return DefaultCryptoKit(
        secret, password_algorithm=password_algorithm, scrypt_params=scrypt_params
    )


def _utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True
