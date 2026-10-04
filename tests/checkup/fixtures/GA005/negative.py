# type: ignore
# ruff: noqa
"""GA005 negative: every payload gets an exp claim, or the visitor cannot tell."""

import os
from datetime import datetime, timedelta, timezone

import jwt

KEY = os.environ["JWT_SECRET"]


def _expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=15)


def create_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id, "exp": _expiry()}, KEY, algorithm="HS256")


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": _expiry()})
    return jwt.encode(to_encode, KEY, algorithm="HS256")


def create_refresh_token(user_id: str) -> str:
    payload = {"sub": user_id}
    payload["exp"] = _expiry()
    return jwt.encode(payload, KEY, algorithm="HS256")


def reissue(claims: dict) -> str:
    return jwt.encode(claims, KEY, algorithm="HS256")
