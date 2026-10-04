# type: ignore
# ruff: noqa
"""Webhook and cookie helpers for the JSON snapshot, with one suppressed finding."""

import hashlib
import hmac


def verify_signature(body: bytes, secret: bytes, signature: str) -> bool:
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return expected == signature


def verify_legacy(body: bytes, secret: bytes, signature: str) -> bool:
    digest = hmac.new(secret, body, hashlib.sha1).hexdigest()
    return digest == signature  # gotauth: ignore[GA006]


def start_session(response, session_id: str) -> None:
    response.set_cookie("session", session_id, httponly=True)
