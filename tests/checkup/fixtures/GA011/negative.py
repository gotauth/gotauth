# type: ignore
# ruff: noqa
"""GA011 negative: the bcrypt default cost (12) or more."""

import bcrypt

BCRYPT_LOG_ROUNDS = 12


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def strong_hash(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=13))
