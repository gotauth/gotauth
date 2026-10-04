# type: ignore
# ruff: noqa
"""GA009 negative: secrets come from the environment; the literals are no secrets."""

import os

SECRET_KEY = os.environ["SECRET_KEY"]
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
TOKEN_URL = "https://auth.example.com/oauth/token"
PASSWORD_MIN_LENGTH = 12
PASSWORD_PATTERN = r"^(?=.*[A-Z])(?=.*\d).{12,}$"
API_KEY_HEADER = "X-API-Key"


def sign_in(client) -> None:
    # Sample passwords in functions (usually tests) are left alone.
    password = "Tr0ub4dor&3xKq9Zp"
    client.post("/login", json={"username": "ada", "password": password})
