# type: ignore
# ruff: noqa
"""GA004 negative: signatures are verified and the algorithms are pinned."""

import os

import jwt

KEY = os.environ["JWT_SECRET"]
PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]


def read_claims(token: str) -> dict:
    return jwt.decode(token, KEY, algorithms=["HS256"])


def read_service_claims(token: str) -> dict:
    return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience="api")
