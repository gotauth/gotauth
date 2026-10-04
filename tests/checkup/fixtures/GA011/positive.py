# type: ignore
# ruff: noqa
"""GA011 positive: bcrypt cost factors below 10."""

import bcrypt

BCRYPT_LOG_ROUNDS = 6


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=8))


def fast_hash(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(4))
