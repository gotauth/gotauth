# type: ignore
# ruff: noqa
"""GA003 negative: the HMAC key comes from the environment, or the key pair is RSA."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

SECRET_KEY = os.environ["JWT_SECRET"]
PRIVATE_KEY = Path("keys/private.pem").read_text()


def _expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=15)


def create_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id, "exp": _expiry()}, SECRET_KEY, algorithm="HS256")


def create_signed_token(user_id: str) -> str:
    return jwt.encode(
        {"sub": user_id, "exp": _expiry()}, PRIVATE_KEY, algorithm="RS256"
    )
