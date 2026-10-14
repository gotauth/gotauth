"""Models of the organization endpoints (work package P5)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

__all__ = [
    "AcceptInvitationIn",
    "CreateOrganizationIn",
    "FullOrganizationOut",
    "InvitationIdIn",
    "InvitationListOut",
    "InvitationOut",
    "InviteMemberIn",
    "MemberOut",
    "OrganizationIdIn",
    "OrganizationListOut",
    "OrganizationOut",
    "RemoveMemberIn",
    "SetActiveIn",
    "SetActiveOut",
    "UpdateMemberRoleIn",
    "UpdateOrganizationIn",
]

_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _email(value: str) -> str:
    """Trimmed and lower-cased, ``local@domain.tld``, at most 254 characters."""
    email = value.strip().lower()
    if len(email) > 254 or not _EMAIL.fullmatch(email):
        raise ValueError("invalid email address")
    return email


Email = Annotated[str, AfterValidator(_email)]

SLUG = r"^[a-z0-9](?:[a-z0-9-]{1,46})[a-z0-9]$"
"""3 to 48 characters of ``[a-z0-9-]``, not starting or ending with ``-``."""


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OrganizationOut(BaseModel):
    """An organization."""

    id: str
    name: str
    slug: str
    logo: str | None
    metadata: dict[str, Any]  # Any: app-defined JSON
    created_at: datetime


class OrganizationWithRoleOut(OrganizationOut):
    """An organization and the caller's role in it."""

    role: str


class OrganizationListOut(BaseModel):
    """``list_organizations`` output."""

    organizations: list[OrganizationWithRoleOut]


class MemberOut(BaseModel):
    """A member, with the user's email and name."""

    id: str
    organization_id: str
    user_id: str
    role: str
    created_at: datetime
    email: str | None = None
    name: str | None = None


class FullOrganizationOut(BaseModel):
    """``get_organization`` output: the organization, its members, the caller's role."""

    organization: OrganizationOut
    members: list[MemberOut]
    role: str


class InvitationOut(BaseModel):
    """An invitation, never its token."""

    id: str
    organization_id: str
    email: str
    role: str
    status: Literal["pending", "accepted", "rejected", "canceled"]
    inviter_id: str | None
    expires_at: datetime
    created_at: datetime


class InvitationListOut(BaseModel):
    """``list_invitations`` output."""

    invitations: list[InvitationOut]


class SetActiveOut(BaseModel):
    """``set_active_organization`` output."""

    organization_id: str | None


class CreateOrganizationIn(_In):
    """``create_organization`` input."""

    name: str = Field(min_length=1, max_length=100)
    slug: str = Field(pattern=SLUG)
    logo: str | None = Field(default=None, max_length=2048)
    metadata: dict[str, Any] | None = None  # Any: app-defined JSON


class OrganizationIdIn(_In):
    """An organization; the active one when omitted."""

    organization_id: str | None = None


class UpdateOrganizationIn(OrganizationIdIn):
    """``update_organization`` input; only the fields given change."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    slug: str | None = Field(default=None, pattern=SLUG)
    logo: str | None = Field(default=None, max_length=2048)
    metadata: dict[str, Any] | None = None  # Any: app-defined JSON


class SetActiveIn(_In):
    """``set_active_organization`` input; ``null`` clears it."""

    organization_id: str | None


class InviteMemberIn(OrganizationIdIn):
    """``invite_member`` input."""

    email: Email
    role: str = Field(default="member", min_length=1, max_length=64)


class AcceptInvitationIn(_In):
    """``accept_invitation`` and ``reject_invitation`` input, from the email link."""

    invitation_id: str
    token: str = Field(min_length=1, max_length=256)


class InvitationIdIn(_In):
    """``cancel_invitation`` input."""

    invitation_id: str


class RemoveMemberIn(OrganizationIdIn):
    """``remove_member`` input."""

    user_id: str


class UpdateMemberRoleIn(OrganizationIdIn):
    """``update_member_role`` input."""

    user_id: str
    role: str = Field(min_length=1, max_length=64)
