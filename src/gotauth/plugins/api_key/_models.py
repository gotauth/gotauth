"""Inputs and outputs of the API key endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from gotauth.contracts.http_models import ApiKeyOut
from gotauth.contracts.primitives import Duration

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
    expires_at: datetime | None = None


class ApiKeyListOut(BaseModel):
    """``list_api_keys`` output."""

    api_keys: list[ApiKeyOut]
