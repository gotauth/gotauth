# type: ignore
# ruff: noqa
"""GA005 positive: tokens that never expire."""

import os

import jwt

KEY = os.environ["JWT_SECRET"]


def create_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id}, KEY, algorithm="HS256")


def create_admin_token(user_id: str) -> str:
    payload = {"sub": user_id, "scope": "admin"}
    return jwt.encode(payload, KEY, algorithm="HS256")
