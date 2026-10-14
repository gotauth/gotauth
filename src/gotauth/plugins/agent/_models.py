"""Input and output models of the agent endpoints (work package O3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from gotauth.contracts.http_models import ApiKeyOut
from gotauth.contracts.primitives import Duration, to_timedelta

__all__ = [
    "AgentApiKeyListOut",
    "AgentListOut",
    "AgentOut",
    "CreateAgentApiKeyIn",
    "CreateAgentIn",
    "LinkOAuthClientIn",
    "ListAgentsIn",
    "RevokeAgentOut",
    "UpdateAgentIn",
]


class AgentOut(BaseModel):
    """An agent (the 12.2 ``agent`` model)."""

    id: str
    name: str
    description: str | None
    owner_type: Literal["user", "organization"]
    owner_id: str
    created_by: str | None
    disabled_at: datetime | None
    created_at: datetime
    metadata: dict[str, Any]  # Any: app-defined JSON


class AgentListOut(BaseModel):
    """``list_agents`` output."""

    agents: list[AgentOut]


class CreateAgentIn(BaseModel):
    """``create_agent`` input: owned by the session user, or by ``organization_id``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=1000)
    organization_id: str | None = None
    metadata: dict[str, Any] | None = None  # Any: app-defined JSON


class ListAgentsIn(BaseModel):
    """``list_agents`` query: the user's agents, or an organization's."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str | None = None


class UpdateAgentIn(BaseModel):
    """``update_agent`` input; only the fields given change. ``enabled=False`` revokes
    the agent like ``revoke_agent``; ``enabled=True`` re-enables it, and what was
    revoked stays revoked."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=1000)
    metadata: dict[str, Any] | None = None  # Any: app-defined JSON
    enabled: bool | None = None


class RevokeAgentOut(BaseModel):
    """``revoke_agent`` output: the agent and what was revoked."""

    agent: AgentOut
    api_keys: int
    oauth_clients: int
    oauth_tokens: int


class CreateAgentApiKeyIn(BaseModel):
    """``create_agent_api_key`` input."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=list[str])
    expires_in: Duration | None = None

    @field_validator("expires_in")
    @classmethod
    def _valid_duration(cls, value: Duration | None) -> Duration | None:
        # A 400 naming the field, never echoing the value (CONTRACTS 6).
        if value is not None:
            try:
                to_timedelta(value)
            except ValueError:
                msg = "expected a duration such as '90s', '15m', '12h' or '7d'"
                raise ValueError(msg) from None
        return value


class LinkOAuthClientIn(BaseModel):
    """``link_oauth_client`` input."""

    model_config = ConfigDict(extra="forbid")

    client_id: str


class AgentApiKeyListOut(BaseModel):
    """``list_agent_api_keys`` output."""

    api_keys: list[ApiKeyOut]
