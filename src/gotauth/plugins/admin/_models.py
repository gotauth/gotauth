"""Models of the admin endpoints (work package P6)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

__all__ = [
    "AdminSessionListOut",
    "AdminSessionOut",
    "AdminUserOut",
    "BanUserIn",
    "CreateUserIn",
    "ImpersonateOut",
    "ListUsersIn",
    "RevokeUserSessionsIn",
    "RevokedOut",
    "SetUserPasswordIn",
    "SetUserRoleIn",
    "StopImpersonatingOut",
    "UserListOut",
]

_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

ROLE = r"^[a-z0-9][a-z0-9_-]{0,31}$"
"""1 to 32 characters of ``[a-z0-9_-]``, starting with a letter or digit."""


def _email(value: str) -> str:
    """Trimmed and lower-cased, ``local@domain.tld``, at most 254 characters."""
    email = value.strip().lower()
    if len(email) > 254 or not _EMAIL.fullmatch(email):
        raise ValueError("invalid email address")
    return email


Email = Annotated[str, AfterValidator(_email)]
Role = Annotated[str, Field(pattern=ROLE)]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AdminUserOut(BaseModel):
    """A user as admins see it, ban fields included."""

    id: str
    email: str
    email_verified: bool
    name: str | None
    image: str | None
    role: str
    banned: bool
    ban_reason: str | None
    ban_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class UserListOut(BaseModel):
    """One page of users and the number of users that match."""

    users: list[AdminUserOut]
    total: int


class ListUsersIn(_In):
    """``list_users`` query.

    ``search`` matches a part of the email (any case) or of the name. Sorting is by
    creation (``created_at``, newest first by default) or by email; both orders are
    total, so paging with ``limit`` and ``offset`` returns every user once.
    """

    search: str | None = Field(default=None, min_length=1, max_length=254)
    sort_by: Literal["created_at", "email"] = "created_at"
    sort_direction: Literal["asc", "desc"] = "desc"
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class CreateUserIn(_In):
    """``create_user`` input. Without a password the user signs in another way."""

    email: Email
    password: str | None = None
    name: str | None = Field(default=None, max_length=255)
    role: Role = "user"
    email_verified: bool = False


class SetUserRoleIn(_In):
    """``set_user_role`` input."""

    role: Role


class SetUserPasswordIn(_In):
    """``set_user_password`` input."""

    new_password: str


class BanUserIn(_In):
    """``ban_user`` input. Without ``expires_in`` the ban lasts until an unban."""

    reason: str | None = Field(default=None, max_length=500)
    expires_in: str | int | None = None


class AdminSessionOut(BaseModel):
    """A session as admins see it. ``impersonated_by`` names the admin, if any."""

    id: str
    user_id: str
    expires_at: datetime
    created_at: datetime
    updated_at: datetime
    ip_address: str | None
    user_agent: str | None
    impersonated_by: str | None


class AdminSessionListOut(BaseModel):
    """A user's sessions, newest first."""

    sessions: list[AdminSessionOut]


class RevokeUserSessionsIn(_In):
    """``revoke_user_sessions`` input: one session, or all of them when omitted."""

    session_id: str | None = None


class RevokedOut(BaseModel):
    """How many sessions were revoked."""

    count: int


class ImpersonateOut(BaseModel):
    """The impersonation session. ``token`` is set for bearer callers, or when
    ``sessions.expose_token`` is on; browsers get the session cookie."""

    user: AdminUserOut
    session: AdminSessionOut
    token: str | None = None


class StopImpersonatingOut(BaseModel):
    """Whether the admin's own session was restored."""

    restored: bool
