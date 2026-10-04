# type: ignore
# ruff: noqa
"""GA004 positive: tokens decoded without verification or pinned algorithms."""

import os

import jwt

KEY = os.environ["JWT_SECRET"]


def read_claims(token: str) -> dict:
    return jwt.decode(token, KEY)


def peek_claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def legacy_claims(token: str) -> dict:
    return jwt.decode(token, KEY, algorithms=["HS256", "none"])
