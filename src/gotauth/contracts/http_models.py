"""CONTRACTS section 13.1 (core endpoint table and response models) and the section 12.5
cross-plugin input and output models.

Cross-plugin input models forbid unknown keys, so a caller that drifts from the frozen
shape fails loudly instead of being silently ignored.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from gotauth.contracts.core_schema import Session, User
from gotauth.contracts.endpoints import EndpointSpec, SignInChallenge
from gotauth.contracts.errors import ErrorBody, ErrorOut
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.principal import Principal

__all__ = [
    "CORE_ENDPOINTS",
    "AccountListOut",
    "AccountOut",
    "ApiKeyOut",
    "ChallengeOut",
    "CreateOAuthClientIn",
    "CreateOAuthClientOut",
    "ErrorBody",
    "ErrorOut",
    "HasPermissionIn",
    "HasPermissionOut",
    "IssueApiKeyIn",
    "IssueApiKeyOut",
    "OAuthClientOut",
    "RedirectOut",
    "RevokeAgentsIn",
    "RevokeApiKeysIn",
    "RevokeOAuthTokensIn",
    "RevokedOut",
    "SessionListOut",
    "SessionOut",
    "SessionWithUserOut",
    "SignInOut",
    "StatusOut",
    "UpdateOAuthClientIn",
    "UpdateOAuthClientOut",
    "UserOut",
    "VerifyAccessTokenIn",
    "VerifyApiKeyIn",
    "VerifyOut",
]

# --- 13.1 response models

UserOut = User
"""A user in API output: the ``User`` record (returned fields, plugin extras kept)."""

SessionOut = Session
"""A session in API output: the ``Session`` record (never the token hash)."""


class SessionWithUserOut(BaseModel):
    """``get_session`` output: ``{session, user}``."""

    session: SessionOut
    user: UserOut


class SignInOut(BaseModel):
    """A completed sign-in. ``token`` is set only with ``sessions.expose_token``."""

    user: UserOut
    session: SessionOut
    token: str | None = None


class ChallengeOut(BaseModel):
    """A sign-in that needs another step: ``{challenge: {type, methods}}``."""

    challenge: SignInChallenge


class StatusOut(BaseModel):
    """``{status}``, e.g. ``"ok"`` or ``"verification_sent"``."""

    status: str


class RedirectOut(BaseModel):
    """``{url}`` the client should navigate to."""

    url: str


class SessionListOut(BaseModel):
    """``list_sessions`` output."""

    sessions: list[SessionOut]
    current_session_id: str | None


class AccountOut(BaseModel):
    """A linked account in ``list_accounts`` output."""

    id: str
    provider_id: str
    account_id: str
    scope: str | None
    created_at: datetime


class AccountListOut(BaseModel):
    """``list_accounts`` output."""

    accounts: list[AccountOut]


# --- 12.5 shapes


class _CallIn(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ApiKeyOut(BaseModel):
    """An API key without its hash (P1 model, ``returned=True`` fields)."""

    id: str
    name: str
    start: str
    owner_type: Literal["user", "organization", "agent"]
    owner_id: str
    user_id: str | None
    scopes: list[str]
    expires_at: datetime | None
    last_used_at: datetime | None
    rate_limit_max: int | None
    rate_limit_window: int | None
    enabled: bool
    created_by: str | None
    created_at: datetime
    metadata: dict[str, Any]  # Any: app-defined JSON
    model_config = ConfigDict(extra="allow")


class OAuthClientOut(BaseModel):
    """An OAuth client without its secret hash (O1 model, ``returned=True`` fields)."""

    id: str
    client_id: str
    type: Literal["public", "confidential"]
    name: str
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: list[str]
    registration: Literal["static", "cimd", "dynamic"]
    agent_id: str | None
    owner_user_id: str | None
    disabled_at: datetime | None
    created_at: datetime
    model_config = ConfigDict(extra="allow")


class IssueApiKeyIn(_CallIn):
    """``issue_api_key`` (P1) input."""

    owner_type: Literal["user", "organization", "agent"]
    owner_id: str
    user_id: str | None = None
    created_by: str | None = None
    name: str
    scopes: list[str]
    expires_in: Duration | None = None
    metadata: dict[str, Any] | None = None  # Any: app-defined JSON

    @field_validator("expires_in")
    @classmethod
    def _valid_duration(cls, value: Duration | None) -> Duration | None:
        # A bad duration is a 400 with the field location, not a crash later. The
        # message must not repeat the value (no input in errors, CONTRACTS 6).
        if value is not None:
            try:
                to_timedelta(value)
            except ValueError:
                msg = "expected a duration such as '90s', '15m', '12h' or '7d'"
                raise ValueError(msg) from None
        return value


class IssueApiKeyOut(BaseModel):
    """``issue_api_key`` output: the key row and the raw key, shown once."""

    api_key: ApiKeyOut
    key: str


class RevokeApiKeysIn(_CallIn):
    """``revoke_api_keys`` (P1) input."""

    owner_type: Literal["user", "organization", "agent"]
    owner_id: str
    key_id: str | None = None


class RevokedOut(BaseModel):
    """``{revoked: int}``, the number of revoked items."""

    revoked: int


class VerifyApiKeyIn(_CallIn):
    """``verify_api_key`` (P1) input."""

    key: str
    scopes: list[str] | None = None


class VerifyOut(BaseModel):
    """``verify_api_key`` and ``verify_access_token`` output."""

    valid: bool
    code: str | None = None
    principal: Principal | None = None


class CreateOAuthClientIn(_CallIn):
    """``create_oauth_client`` (O1) input."""

    name: str
    type: Literal["public", "confidential"]
    redirect_uris: list[str]
    grant_types: list[str] | None = None
    scopes: list[str] | None = None
    owner_user_id: str | None = None
    agent_id: str | None = None


class CreateOAuthClientOut(BaseModel):
    """``create_oauth_client`` output; ``client_secret`` only for confidential ones."""

    client: OAuthClientOut
    client_secret: str | None = None


class UpdateOAuthClientIn(_CallIn):
    """``update_oauth_client`` (O1) input.

    Only the keys present are changed: check ``model_fields_set``. An explicit
    ``agent_id: null`` unlinks the agent.
    """

    client_id: str
    name: str | None = None
    redirect_uris: list[str] | None = None
    scopes: list[str] | None = None
    agent_id: str | None = None
    disabled: bool | None = None


class UpdateOAuthClientOut(BaseModel):
    """``update_oauth_client`` output."""

    client: OAuthClientOut


class RevokeOAuthTokensIn(_CallIn):
    """``revoke_oauth_tokens`` (O1) input; at least one key is required."""

    client_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    family_id: str | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> RevokeOAuthTokensIn:
        given = (self.client_id, self.user_id, self.agent_id, self.family_id)
        if all(value is None for value in given):
            msg = "give at least one of client_id, user_id, agent_id, family_id"
            raise ValueError(msg)
        return self


class VerifyAccessTokenIn(_CallIn):
    """``verify_access_token`` (O1) input."""

    token: str
    resource: str | None = None
    scopes: list[str] | None = None


class RevokeAgentsIn(_CallIn):
    """``revoke_agents`` (O3) input."""

    owner_type: Literal["user", "organization"]
    owner_id: str


class HasPermissionIn(_CallIn):
    """``has_permission`` (P5) input: ``{organization_id?, permissions: {resource:
    [action]}}``."""

    organization_id: str | None = None
    permissions: dict[str, list[str]]


class HasPermissionOut(BaseModel):
    """``has_permission`` output; a denial is ``success=false``, not an error."""

    success: bool


# --- 13.1 table

CORE_ENDPOINTS: tuple[EndpointSpec, ...] = (
    EndpointSpec(
        "sign_up_email",
        "POST",
        "/sign-up/email",
        "none",
        "C2",
        output=(SignInOut, StatusOut),
    ),
    EndpointSpec(
        "sign_in_email",
        "POST",
        "/sign-in/email",
        "none",
        "C2",
        output=(SignInOut, ChallengeOut),
    ),
    EndpointSpec("sign_out", "POST", "/sign-out", "session", "C2", output=(StatusOut,)),
    EndpointSpec(
        "send_verification_email",
        "POST",
        "/send-verification-email",
        "none",
        "C2",
        output=(StatusOut,),
    ),
    EndpointSpec(
        "verify_email",
        "GET",
        "/verify-email",
        "none",
        "C2",
        output=("redirect", StatusOut),
    ),
    EndpointSpec(
        "request_password_reset",
        "POST",
        "/request-password-reset",
        "none",
        "C2",
        output=(StatusOut,),
    ),
    EndpointSpec(
        "reset_password", "POST", "/reset-password", "none", "C2", output=(StatusOut,)
    ),
    EndpointSpec(
        "change_password",
        "POST",
        "/change-password",
        "session",
        "C2",
        fresh_session=True,
        output=(StatusOut,),
    ),
    EndpointSpec(
        "change_email",
        "POST",
        "/change-email",
        "session",
        "C2",
        fresh_session=True,
        output=(StatusOut,),
    ),
    EndpointSpec("update_user", "PATCH", "/user", "session", "C2", output=(UserOut,)),
    EndpointSpec(
        "delete_user",
        "DELETE",
        "/user",
        "session",
        "C2",
        fresh_session=True,
        input_format="json",
        output=(StatusOut,),
    ),
    EndpointSpec(
        "get_session",
        "GET",
        "/session",
        "optional",
        "C3",
        output=(SessionWithUserOut, "null"),
    ),
    EndpointSpec(
        "list_sessions", "GET", "/sessions", "session", "C3", output=(SessionListOut,)
    ),
    EndpointSpec(
        "revoke_session",
        "POST",
        "/sessions/revoke",
        "session",
        "C3",
        output=(StatusOut,),
    ),
    EndpointSpec(
        "revoke_other_sessions",
        "POST",
        "/sessions/revoke-others",
        "session",
        "C3",
        output=(StatusOut,),
    ),
    EndpointSpec(
        "sign_in_social", "POST", "/sign-in/social", "none", "C4", output=(RedirectOut,)
    ),
    EndpointSpec(
        "social_callback",
        "GET",
        "/callback/{provider}",
        "none",
        "C4",
        output=("redirect",),
    ),
    EndpointSpec(
        "social_callback_post",
        "POST",
        "/callback/{provider}",
        "none",
        "C4",
        input_format="form",
        output=("redirect",),
    ),
    EndpointSpec(
        "link_social", "POST", "/link-social", "session", "C4", output=(RedirectOut,)
    ),
    EndpointSpec(
        "list_accounts", "GET", "/accounts", "session", "C4", output=(AccountListOut,)
    ),
    EndpointSpec(
        "unlink_account",
        "POST",
        "/unlink-account",
        "session",
        "C4",
        fresh_session=True,
        output=(StatusOut,),
    ),
)
"""The core endpoints of section 13.1, in table order."""
