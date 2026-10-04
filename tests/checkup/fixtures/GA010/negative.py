# type: ignore
# ruff: noqa
"""GA010 negative: fast digests for tokens and files, scrypt for passwords."""

import hashlib
import os


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def file_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
