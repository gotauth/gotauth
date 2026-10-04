# type: ignore
# ruff: noqa
"""GA006 positive: secrets compared with == and !=."""

import hashlib
import hmac


def check_api_key(provided_api_key: str, stored_api_key: str) -> bool:
    return provided_api_key == stored_api_key


def verify_webhook(body: bytes, secret: bytes, headers: dict) -> bool:
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return expected == headers["X-Signature"]


def check_reset(user, token: str) -> None:
    if user.reset_token != token:
        raise PermissionError("invalid reset link")
