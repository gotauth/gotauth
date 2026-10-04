# type: ignore
# ruff: noqa
"""GA003 positive: HMAC-signed tokens with secrets in the source."""

import os
from datetime import datetime, timedelta, timezone

import jwt

SIGNING_KEY = "not-long-enough"
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")


def _expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=15)


def create_token(user_id: str) -> str:
    return jwt.encode(
        {"sub": user_id, "exp": _expiry()}, SIGNING_KEY, algorithm="HS256"
    )


def create_refresh_token(user_id: str) -> str:
    # No algorithm: PyJWT defaults to HS256.
    return jwt.encode({"sub": user_id, "exp": _expiry()}, "refresh-secret")


def create_api_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id, "exp": _expiry()}, JWT_SECRET, algorithm="HS512")
