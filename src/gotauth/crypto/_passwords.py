"""Password hashing and verification (CONTRACTS section 8).

Stored formats, each with a tag in front:

- ``scrypt$ln=15,r=8,p=3$<salt>$<hash>``: the default. Standard base64 without padding,
  16-byte salt, 64-byte key, N = 2**ln.
- ``argon2id$<PHC string>``: with the ``argon2`` extra and
  ``password_algorithm="argon2id"``.
- ``bcrypt$<$2a$, $2b$ or $2y$ hash>``: verify only, for imported users.

Everything here is synchronous and CPU-bound. The kit runs it in a worker thread.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from gotauth.contracts.crypto import PasswordCheck
from gotauth.crypto._encoding import b64_decode, b64_encode
from gotauth.crypto._errors import ConfigError

if TYPE_CHECKING:
    import argon2

__all__ = [
    "ARGON2_INSTALL_HINT",
    "BCRYPT_INSTALL_HINT",
    "BCRYPT_MAX_PASSWORD_BYTES",
    "DEFAULT_SCRYPT",
    "MAX_SCRYPT_LN",
    "PASSWORD_ALGORITHMS",
    "SCRYPT_KEY_BYTES",
    "SCRYPT_SALT_BYTES",
    "PasswordAlgorithm",
    "PasswordCheck",
    "PasswordHasher",
    "ScryptParams",
    "format_scrypt",
    "parse_scrypt",
    "scrypt_derive",
    "scrypt_maxmem",
]

PasswordAlgorithm = Literal["scrypt", "argon2id"]
"""Algorithms for new password hashes. Verification accepts every format above."""

PASSWORD_ALGORITHMS: tuple[PasswordAlgorithm, ...] = ("scrypt", "argon2id")

ARGON2_INSTALL_HINT = 'install the argon2 extra: pip install "gotauth[argon2]"'
BCRYPT_INSTALL_HINT = 'install the bcrypt extra: pip install "gotauth[bcrypt]"'


@dataclass(frozen=True)
class ScryptParams:
    """scrypt cost parameters (RFC 7914).

    Attributes:
        ln: log2 of the CPU and memory cost N.
        r: Block size.
        p: Parallelization.
    """

    ln: int
    r: int
    p: int

    @property
    def n(self) -> int:
        """The CPU and memory cost N = 2**ln."""
        return 1 << self.ln


DEFAULT_SCRYPT = ScryptParams(ln=15, r=8, p=3)
SCRYPT_SALT_BYTES = 16
SCRYPT_KEY_BYTES = 64
# N = 2**15 with r = 8 needs 32 MiB plus a little, just over OpenSSL's default limit.
_SCRYPT_MIN_MAXMEM = 64 * 1024 * 1024

# Limits for parsed hashes, so a corrupted or hostile stored value cannot make one
# verification allocate gigabytes or run for minutes.
MAX_SCRYPT_LN = 20
_MAX_SCRYPT_R = 32
_MAX_SCRYPT_P = 16
_MAX_SCRYPT_BLOCK_MEMORY = 1 << 30  # 128 * r * N; ln = 20 with r = 8 is exactly 1 GiB
_SCRYPT_SALT_RANGE = range(8, 129)
_SCRYPT_KEY_RANGE = range(16, 129)
_SCRYPT_PARAMS = re.compile(r"ln=([1-9][0-9]?),r=([1-9][0-9]{0,2}),p=([1-9][0-9]{0,2})")

# bcrypt reads at most 72 bytes; passlib silently hashed only those, bcrypt 5 raises.
BCRYPT_MAX_PASSWORD_BYTES = 72
_BCRYPT_COST_RANGE = range(4, 17)
# $2x$ is the variant for the old sign-extension bug; nothing should still produce it.
_BCRYPT_HASH = re.compile(r"\$2[aby]\$([0-9]{2})\$[./A-Za-z0-9]{53}")

_ARGON2_MAX_MEMORY_KIB = 1 << 20
_ARGON2_MAX_TIME_COST = 32
_ARGON2_MAX_PARALLELISM = 32


def scrypt_maxmem(params: ScryptParams) -> int:
    """Return the ``maxmem`` to pass to ``hashlib.scrypt`` for these parameters.

    OpenSSL counts ``128 * r * (N + 2)`` bytes for its V array plus ``128 * r * p``
    for B and refuses anything over ``maxmem``. Its default limit (32 MiB) rejects the
    default cost, so the limit is raised to what the parameters need, at least 64 MiB.

    Args:
        params: The cost parameters.

    Returns:
        A byte count for ``maxmem``.
    """
    needed = 128 * params.r * (params.n + 2 + params.p) + (1 << 20)
    return max(_SCRYPT_MIN_MAXMEM, needed)


def scrypt_derive(
    password: bytes, salt: bytes, params: ScryptParams, length: int
) -> bytes:
    """Run scrypt (RFC 7914) with ``hashlib.scrypt``.

    Args:
        password: The password bytes.
        salt: The salt bytes.
        params: The cost parameters.
        length: Output length in bytes.

    Returns:
        The derived key.
    """
    return hashlib.scrypt(
        password,
        salt=salt,
        n=params.n,
        r=params.r,
        p=params.p,
        maxmem=scrypt_maxmem(params),
        dklen=length,
    )


def format_scrypt(params: ScryptParams, salt: bytes, key: bytes) -> str:
    """Format a stored scrypt hash.

    Args:
        params: The cost parameters.
        salt: The salt.
        key: The derived key.

    Returns:
        ``scrypt$ln=<ln>,r=<r>,p=<p>$<b64 salt>$<b64 key>``, base64 without padding.
    """
    cost = f"ln={params.ln},r={params.r},p={params.p}"
    return f"scrypt${cost}${b64_encode(salt)}${b64_encode(key)}"


def _scrypt_params_allowed(params: ScryptParams) -> bool:
    return (
        1 <= params.ln <= MAX_SCRYPT_LN
        and 1 <= params.r <= _MAX_SCRYPT_R
        and 1 <= params.p <= _MAX_SCRYPT_P
        and 128 * params.r * params.n <= _MAX_SCRYPT_BLOCK_MEMORY
    )


def parse_scrypt(body: str) -> tuple[ScryptParams, bytes, bytes] | None:
    """Parse the part of a stored scrypt hash after ``scrypt$``.

    Args:
        body: ``ln=<ln>,r=<r>,p=<p>$<b64 salt>$<b64 key>``.

    Returns:
        ``(params, salt, key)``, or None if the text is malformed or the cost is over
        the limits (ln at most 20, r at most 32, p at most 16, 128 * r * N at most
        1 GiB).
    """
    parts = body.split("$")
    if len(parts) != 3:
        return None
    match = _SCRYPT_PARAMS.fullmatch(parts[0])
    if match is None:
        return None
    params = ScryptParams(ln=int(match[1]), r=int(match[2]), p=int(match[3]))
    if not _scrypt_params_allowed(params):
        return None
    try:
        salt = b64_decode(parts[1])
        key = b64_decode(parts[2])
    except ValueError:
        return None
    if len(salt) not in _SCRYPT_SALT_RANGE or len(key) not in _SCRYPT_KEY_RANGE:
        return None
    return params, salt, key


def _encode_password(password: str) -> bytes:
    try:
        return password.encode("utf-8")
    except UnicodeEncodeError:
        # "from None": the codec's message quotes the offending character.
        msg = "password is not valid Unicode"
        raise ValueError(msg) from None


def _new_argon2_hasher(action: str) -> argon2.PasswordHasher:
    try:
        import argon2  # optional extra, imported only when used
    except ImportError:
        msg = f"{action} needs argon2-cffi; {ARGON2_INSTALL_HINT}"
        raise ConfigError(msg) from None
    # argon2-cffi's defaults are the RFC 9106 low-memory profile (t=3, m=64 MiB, p=4).
    return argon2.PasswordHasher()


def _bcrypt_checkpw() -> Callable[[bytes, bytes], bool]:
    try:
        import bcrypt  # optional extra, imported only when used
    except ImportError:
        msg = f"verifying a bcrypt password hash needs bcrypt; {BCRYPT_INSTALL_HINT}"
        raise ConfigError(msg) from None
    return bcrypt.checkpw


class PasswordHasher:
    """Hashes and verifies passwords synchronously in one configured algorithm.

    The crypto kit calls these methods through ``asyncio.to_thread``; call them
    directly only outside an event loop.
    """

    __slots__ = ("_algorithm", "_argon2", "_random_bytes", "_scrypt")

    def __init__(
        self,
        algorithm: PasswordAlgorithm = "scrypt",
        *,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        scrypt: ScryptParams = DEFAULT_SCRYPT,
    ) -> None:
        """Create a hasher.

        Args:
            algorithm: The algorithm for new hashes.
            random_bytes: Source of salt bytes; tests replace it.
            scrypt: Parameters for new scrypt hashes; a stored hash with different
                parameters reports ``needs_rehash``. Lower them only in tests.

        Raises:
            ConfigError: If the algorithm is unknown, or is ``"argon2id"`` without the
                ``argon2`` extra installed.
        """
        if algorithm not in PASSWORD_ALGORITHMS:
            msg = f"password_algorithm must be one of {', '.join(PASSWORD_ALGORITHMS)}"
            raise ConfigError(msg)
        self._algorithm: PasswordAlgorithm = algorithm
        self._random_bytes = random_bytes
        self._scrypt = scrypt
        self._argon2: argon2.PasswordHasher | None = (
            _new_argon2_hasher("password_algorithm 'argon2id'")
            if algorithm == "argon2id"
            else None
        )

    @property
    def algorithm(self) -> PasswordAlgorithm:
        """The algorithm used for new hashes."""
        return self._algorithm

    def hash(self, password: str) -> str:
        """Hash a password with the configured algorithm and a fresh salt.

        Args:
            password: The password.

        Returns:
            The tagged stored form, for example ``scrypt$ln=15,r=8,p=3$...``.

        Raises:
            ValueError: If the password cannot be encoded as UTF-8 (lone surrogates).
        """
        return self._hash_bytes(_encode_password(password))

    def verify(self, password: str, stored: str) -> PasswordCheck:
        """Verify a password against a stored hash.

        An empty ``stored`` (unknown user), an unknown tag, a malformed hash or a
        hash over the cost limits all give ``ok=False``, after a full hash with the
        configured algorithm so they take as long as a wrong password.

        Args:
            password: The password the user sent.
            stored: The stored hash, or ``""`` when the user does not exist.

        Returns:
            Whether the password matched and whether the hash should be replaced.

        Raises:
            ConfigError: If ``stored`` is an argon2id or bcrypt hash and the extra
                that verifies it is not installed.
        """
        try:
            secret: bytes | None = _encode_password(password)
        except ValueError:
            secret = None
        result = None if secret is None else self._check(secret, stored)
        if result is None:
            self._hash_bytes(password.encode("utf-8", "surrogatepass"))
            return PasswordCheck(ok=False, needs_rehash=False)
        ok, outdated = result
        return PasswordCheck(ok=ok, needs_rehash=ok and outdated)

    def _hash_bytes(self, secret: bytes) -> str:
        if self._argon2 is not None:
            return "argon2id$" + self._argon2.hash(secret)
        salt = self._random_bytes(SCRYPT_SALT_BYTES)
        key = scrypt_derive(secret, salt, self._scrypt, SCRYPT_KEY_BYTES)
        return format_scrypt(self._scrypt, salt, key)

    def _check(self, secret: bytes, stored: str) -> tuple[bool, bool] | None:
        """Return ``(ok, outdated)``, or None when ``stored`` is not a usable hash."""
        tag, separator, body = stored.partition("$")
        if not separator:
            return None
        if tag == "scrypt":
            return self._check_scrypt(secret, body)
        if tag == "argon2id":
            return self._check_argon2(secret, body)
        if tag == "bcrypt":
            return self._check_bcrypt(secret, body)
        return None

    def _check_scrypt(self, secret: bytes, body: str) -> tuple[bool, bool] | None:
        parsed = parse_scrypt(body)
        if parsed is None:
            return None
        params, salt, key = parsed
        ok = hmac.compare_digest(scrypt_derive(secret, salt, params, len(key)), key)
        outdated = (
            self._algorithm != "scrypt"
            or params != self._scrypt
            or len(salt) != SCRYPT_SALT_BYTES
            or len(key) != SCRYPT_KEY_BYTES
        )
        return ok, outdated

    def _check_argon2(self, secret: bytes, phc: str) -> tuple[bool, bool] | None:
        hasher = self._argon2 or _new_argon2_hasher(
            "verifying an argon2id password hash"
        )
        from argon2 import extract_parameters  # optional extra
        from argon2.exceptions import (  # optional extra
            InvalidHashError,
            VerificationError,
            VerifyMismatchError,
        )

        if not phc.startswith("$argon2id$"):
            return None
        try:
            params = extract_parameters(phc)
        except InvalidHashError:
            return None
        if (
            params.memory_cost > _ARGON2_MAX_MEMORY_KIB
            or params.time_cost > _ARGON2_MAX_TIME_COST
            or params.parallelism > _ARGON2_MAX_PARALLELISM
        ):
            return None
        try:
            hasher.verify(phc, secret)
        except VerifyMismatchError:
            return False, False
        except (VerificationError, InvalidHashError):
            return None
        outdated = self._algorithm != "argon2id" or hasher.check_needs_rehash(phc)
        return True, outdated

    def _check_bcrypt(self, secret: bytes, body: str) -> tuple[bool, bool] | None:
        match = _BCRYPT_HASH.fullmatch(body)
        if match is None or int(match[1]) not in _BCRYPT_COST_RANGE:
            return None
        checkpw = _bcrypt_checkpw()
        try:
            ok = checkpw(secret[:BCRYPT_MAX_PASSWORD_BYTES], body.encode("ascii"))
        except ValueError:
            return None
        # bcrypt is verify-only: a match always asks for a new hash.
        return ok, True
