"""Row mapping from the fastapi-users schema to GotAuth (work package I1).

Pure functions: no database, no crypto keys.
"""

from __future__ import annotations

import importlib.util
import re
import uuid
from datetime import UTC, datetime
from typing import Literal

__all__ = [
    "HashKind",
    "argon2_available",
    "bcrypt_available",
    "canonical_id",
    "convert_hash",
    "expires_at",
    "hash_kind",
    "normalize_email",
]

HashKind = Literal["bcrypt", "argon2id", "unknown"]

# The same forms F3 verifies: $2a$, $2b$ and $2y$ with a two-digit cost.
_BCRYPT = re.compile(r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}")
# pwdlib and passlib both write the PHC string of argon2-cffi.
_ARGON2ID = re.compile(
    r"\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+"
)


def canonical_id(value: object) -> str:
    """The GotAuth id for a source id: the canonical UUID string (lower case, with
    hyphens), which is how fastapi-users stores it, so foreign keys still match.
    A value that is not a UUID is kept as its string."""
    if isinstance(value, uuid.UUID):
        return str(value)
    text = str(value)
    try:
        return str(uuid.UUID(text))
    except ValueError:
        return text


def normalize_email(value: str) -> str:
    """Trimmed and lower-cased, as GotAuth stores emails."""
    return value.strip().lower()


def hash_kind(hashed: str | None) -> HashKind:
    """Which password hash format a fastapi-users ``hashed_password`` is."""
    if not hashed:
        return "unknown"
    if _BCRYPT.fullmatch(hashed):
        return "bcrypt"
    if _ARGON2ID.fullmatch(hashed):
        return "argon2id"
    return "unknown"


def convert_hash(hashed: str) -> str | None:
    """The tagged GotAuth form of a source hash (CONTRACTS 8), or None when GotAuth
    cannot verify it."""
    kind = hash_kind(hashed)
    if kind == "unknown":
        return None
    return f"{kind}${hashed}"


def argon2_available() -> bool:
    """Whether the ``argon2`` extra is installed, so argon2id hashes can be verified."""
    return importlib.util.find_spec("argon2") is not None


def bcrypt_available() -> bool:
    """Whether the ``bcrypt`` extra is installed, so bcrypt hashes can be verified."""
    return importlib.util.find_spec("bcrypt") is not None


def expires_at(epoch: object) -> datetime | None:
    """fastapi-users keeps the access token expiry as epoch seconds."""
    if epoch is None or isinstance(epoch, bool):
        return None
    try:
        return datetime.fromtimestamp(float(str(epoch)), tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None
