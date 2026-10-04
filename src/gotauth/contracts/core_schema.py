"""CONTRACTS sections 2.1 and 2.2: the core models and their record types."""

from __future__ import annotations

from datetime import datetime
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ConfigDict

from gotauth.contracts.schema import Field, ModelSchema, Reference, Schema

__all__ = [
    "ACCOUNT_MODEL",
    "CORE_SCHEMA",
    "SESSION_MODEL",
    "USER_MODEL",
    "VERIFICATION_MODEL",
    "Account",
    "Session",
    "User",
    "Verification",
]

_USER = Reference("user", on_delete="cascade")

USER_MODEL = ModelSchema(
    name="user",
    fields=MappingProxyType(
        {
            # Stored lower-case; create_user_record (C1) normalizes it.
            "email": Field("string", unique=True),
            "email_verified": Field("boolean", default=False, input=False),
            "name": Field("string", required=False),
            "image": Field("string", required=False),
            "created_at": Field("datetime", input=False),
            "updated_at": Field("datetime", input=False),
        }
    ),
)

ACCOUNT_MODEL = ModelSchema(
    name="account",
    fields=MappingProxyType(
        {
            "user_id": Field("string", references=_USER),
            # "credential" for email + password.
            "provider_id": Field("string"),
            # The provider's user id, or the user id for credentials.
            "account_id": Field("string"),
            "password_hash": Field("string", required=False, returned=False),
            # AES-GCM, purpose "account_token"; only with store_provider_tokens=True.
            "access_token_enc": Field("text", required=False, returned=False),
            "refresh_token_enc": Field("text", required=False, returned=False),
            "id_token_enc": Field("text", required=False, returned=False),
            "access_token_expires_at": Field("datetime", required=False),
            "scope": Field("string", required=False),
            "created_at": Field("datetime"),
            "updated_at": Field("datetime"),
        }
    ),
    unique_together=(("provider_id", "account_id"),),
)

SESSION_MODEL = ModelSchema(
    name="session",
    fields=MappingProxyType(
        {
            "user_id": Field("string", references=_USER),
            "token_hash": Field("string", unique=True, returned=False),
            "expires_at": Field("datetime"),
            "remember_me": Field("boolean", default=True),
            "created_at": Field("datetime"),
            "updated_at": Field("datetime"),
            "ip_address": Field("string", required=False),
            "user_agent": Field("string", required=False),
        }
    ),
)

VERIFICATION_MODEL = ModelSchema(
    name="verification",
    fields=MappingProxyType(
        {
            "identifier": Field("string", index=True),
            # Long tokens: hash_token(token).
            # Short codes: hash_token(identifier + ":" + code).
            "value_hash": Field("string", unique=True, returned=False),
            "expires_at": Field("datetime"),
            "created_at": Field("datetime"),
            "attempts": Field("integer", default=0),
            "data": Field("json", required=False),
        }
    ),
)

CORE_SCHEMA: Schema = MappingProxyType(
    {
        "user": USER_MODEL,
        "account": ACCOUNT_MODEL,
        "session": SESSION_MODEL,
        "verification": VERIFICATION_MODEL,
    }
)
"""The core models of section 2.1. Plugins extend them through ``merge_schemas``."""


class User(BaseModel):
    """A user record. Plugin fields with ``returned=True`` are kept as extras."""

    id: str
    email: str
    email_verified: bool
    name: str | None
    image: str | None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(extra="allow")


class Session(BaseModel):
    """A session record. The token hash is never part of it."""

    id: str
    user_id: str
    expires_at: datetime
    remember_me: bool
    created_at: datetime
    updated_at: datetime
    ip_address: str | None
    user_agent: str | None
    model_config = ConfigDict(extra="allow")


class Account(BaseModel):
    """An account record. The password hash and provider tokens are never part of it."""

    id: str
    user_id: str
    provider_id: str
    account_id: str
    access_token_expires_at: datetime | None
    scope: str | None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(extra="allow")


class Verification(BaseModel):
    """A verification record. The value hash is never part of it."""

    id: str
    identifier: str
    expires_at: datetime
    created_at: datetime
    attempts: int
    data: Any  # Any: any JSON value (an object, or an encrypted string for C4's state)
    model_config = ConfigDict(extra="allow")
