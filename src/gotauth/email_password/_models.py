"""Input models of the email + password endpoints (CONTRACTS 13.1, C2 rows)."""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict

__all__ = [
    "ChangeEmailIn",
    "ChangePasswordIn",
    "DeleteUserIn",
    "Email",
    "RequestPasswordResetIn",
    "ResetPasswordIn",
    "SendVerificationEmailIn",
    "SignInEmailIn",
    "SignUpEmailIn",
    "UpdateUserIn",
    "VerifyEmailIn",
    "normalize_email",
]

_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_MAX_EMAIL = 254


def normalize_email(value: str) -> str:
    """Trim and lower-case an email address and check its basic shape.

    Raises:
        ValueError: When the address is too long or not ``local@domain.tld``.
    """
    email = value.strip().lower()
    if len(email) > _MAX_EMAIL or not _EMAIL.fullmatch(email):
        raise ValueError("invalid email address")
    return email


Email = Annotated[str, AfterValidator(normalize_email)]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SignUpEmailIn(_In):
    """``sign_up_email`` input."""

    email: Email
    password: str
    name: str | None = None
    image: str | None = None
    callback_url: str | None = None
    remember_me: bool = True


class SignInEmailIn(_In):
    """``sign_in_email`` input."""

    email: Email
    password: str
    remember_me: bool = True


class SendVerificationEmailIn(_In):
    """``send_verification_email`` input."""

    email: Email
    callback_url: str | None = None


class VerifyEmailIn(BaseModel):
    """``verify_email`` query parameters.

    Unknown parameters are ignored: mail providers add tracking ones to links.
    """

    model_config = ConfigDict(extra="ignore")

    token: str
    callback_url: str | None = None


class RequestPasswordResetIn(_In):
    """``request_password_reset`` input."""

    email: Email
    redirect_to: str


class ResetPasswordIn(_In):
    """``reset_password`` input."""

    token: str
    new_password: str


class ChangePasswordIn(_In):
    """``change_password`` input."""

    current_password: str
    new_password: str
    revoke_other_sessions: bool = False


class ChangeEmailIn(_In):
    """``change_email`` input."""

    new_email: Email
    callback_url: str | None = None


class UpdateUserIn(_In):
    """``update_user`` input. The email changes only through ``change_email``."""

    name: str | None = None
    image: str | None = None


class DeleteUserIn(_In):
    """``delete_user`` input; ``password`` is required for credential accounts."""

    password: str | None = None
