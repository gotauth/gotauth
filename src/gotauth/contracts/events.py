"""CONTRACTS section 14: audit events."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, TypeAlias, cast, get_args

if TYPE_CHECKING:
    from gotauth.contracts.principal import Principal

__all__ = ["AUTH_EVENT_TYPES", "AuthEvent", "AuthEventType"]

AuthEventType: TypeAlias = Literal[
    "user.created",
    "user.updated",
    "user.deleted",
    "user.email_verified",
    "user.email_changed",
    "user.role_changed",
    "user.banned",
    "user.unbanned",
    "sign_in.succeeded",
    "sign_in.failed",
    "sign_out",
    "password.changed",
    "password.reset",
    "session.revoked",
    "account.linked",
    "account.unlinked",
    "two_factor.enabled",
    "two_factor.disabled",
    "passkey.added",
    "passkey.removed",
    "api_key.created",
    "api_key.revoked",
    "agent.created",
    "agent.revoked",
    "oauth.consent_granted",
    "oauth.token_revoked",
    "oauth.client_created",
    "org.created",
    "org.deleted",
    "org.member_added",
    "org.member_removed",
    "org.role_changed",
    "org.invitation_sent",
    "org.invitation_accepted",
    "admin.impersonation_started",
    "admin.impersonation_stopped",
]
AUTH_EVENT_TYPES: tuple[AuthEventType, ...] = cast(
    "tuple[AuthEventType, ...]", get_args(AuthEventType)
)


@dataclass(frozen=True)
class AuthEvent:
    """An event delivered to ``on_event`` after the transaction commits.

    Attributes:
        id: ``"evt_..."``.
        type: The event type.
        at: When it happened (UTC).
        user_id: The user concerned, if any.
        principal: Who acted; carries ``agent_id`` when an agent acted.
        ip_address: The client IP.
        user_agent: The client user agent.
        data: Event details. Never secrets.
    """

    id: str
    type: AuthEventType
    at: datetime
    user_id: str | None
    principal: Principal | None
    ip_address: str | None
    user_agent: str | None
    # Any: event details are arbitrary JSON values.
    data: Mapping[str, Any] = dc_field(default_factory=dict[str, Any])
