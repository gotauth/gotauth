# type: ignore
# ruff: noqa
"""GA010 positive: passwords stored as fast digests."""

import hashlib


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()


def legacy_hash(user) -> str:
    return hashlib.md5(user.password.encode()).hexdigest()


def incremental_hash(pwd: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(pwd)
    return digest.hexdigest()
