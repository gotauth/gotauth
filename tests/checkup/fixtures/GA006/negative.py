# type: ignore
# ruff: noqa
"""GA006 negative: constant-time comparisons and comparisons that are no secret."""

import hmac


def check_api_key(provided_api_key: str, stored_api_key: str) -> bool:
    return hmac.compare_digest(provided_api_key, stored_api_key)


def validate_sign_up(password: str, confirm_password: str) -> None:
    if password != confirm_password:
        raise ValueError("the passwords do not match")


def validate_change(new_password: str, old_password: str) -> None:
    if new_password == old_password:
        raise ValueError("choose a new password")


def parse_authorization(header: str) -> str | None:
    scheme, _, token = header.partition(" ")
    if token == "" or token is None:
        return None
    if scheme.lower() != "bearer":
        return None
    return token


def within_budget(response, max_tokens: int) -> bool:
    return response.usage.total_tokens == max_tokens


def is_refresh(token) -> bool:
    return token.token_type == "refresh"


def test_round_trip(token: str, decoded: dict) -> None:
    assert decoded["token"] == token
