"""Email and password sign-up, sign-in, email verification and password reset (C2).

See README.md for the account enumeration rules these endpoints follow.
"""

from __future__ import annotations

from ._models import (
    ChangeEmailIn,
    ChangePasswordIn,
    DeleteUserIn,
    RequestPasswordResetIn,
    ResetPasswordIn,
    SendVerificationEmailIn,
    SignInEmailIn,
    SignUpEmailIn,
    UpdateUserIn,
    VerifyEmailIn,
    normalize_email,
)
from ._plugin import CREDENTIAL_PROVIDER, email_password_plugin
from ._tokens import VERIFICATION_PREFIX

__all__ = [
    "CREDENTIAL_PROVIDER",
    "VERIFICATION_PREFIX",
    "ChangeEmailIn",
    "ChangePasswordIn",
    "DeleteUserIn",
    "RequestPasswordResetIn",
    "ResetPasswordIn",
    "SendVerificationEmailIn",
    "SignInEmailIn",
    "SignUpEmailIn",
    "UpdateUserIn",
    "VerifyEmailIn",
    "email_password_plugin",
    "normalize_email",
]
