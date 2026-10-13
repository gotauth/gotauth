"""Inputs and outputs of the API key endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from gotauth.contracts.http_models import ApiKeyOut
from gotauth.contracts.primitives import Duration, to_timedelta

__all__ = ["ApiKeyListOut", "CreateApiKeyIn", "ListApiKeysIn", "UpdateApiKeyIn"]


class CreateApiKeyIn(BaseModel):
    """``create_api_key`` input."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=list[str])
    expires_in: Duration | None = None
    organization_id: str | None = None
    metadata: dict[str, Any] | None = None  # Any: app-defined JSON
    rate_limit_max: int | None = Field(default=None, ge=1)
    rate_limit_window: int | None = Field(default=None, ge=1)  # seconds

    @field_validator("expires_in")
    @classmethod
    def _valid_duration(cls, value: Duration | None) -> Duration | None:
        # A bad duration is a 400 with the field location, not a crash later.
        if value is not None:
            to_timedelta(value)
        return value


class ListApiKeysIn(BaseModel):
    """``list_api_keys`` query."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str | None = None


class UpdateApiKeyIn(BaseModel):
    """``update_api_key`` input; only the fields given change."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=100)
    scopes: list[str] | None = None
    enabled: bool | None = None
    expires_at: AwareDatetime | None = None


class ApiKeyListOut(BaseModel):
    """``list_api_keys`` output."""

    api_keys: list[ApiKeyOut]
