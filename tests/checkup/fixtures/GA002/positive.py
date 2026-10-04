# type: ignore
# ruff: noqa
"""GA002 positive: tokens through python-jose (otherwise written carefully)."""

import os
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

SECRET_KEY = os.environ["SECRET_KEY"]


def create_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    return jwt.encode({"sub": user_id, "exp": expire}, SECRET_KEY, algorithm="HS256")


def read_subject(token: str) -> str | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"]).get("sub")
    except JWTError:
        return None
