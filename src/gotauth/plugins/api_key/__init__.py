"""API keys: scoped, revocable, hashed at rest and shown once (work package P1).

from gotauth.plugins.api_key import api_key

auth = GotAuth(..., plugins=[api_key(allowed_scopes=["projects:read"])])
"""

from __future__ import annotations

from ._models import ApiKeyListOut, CreateApiKeyIn, ListApiKeysIn, UpdateApiKeyIn
from ._plugin import API_KEY_PREFIX, ERROR_CODES, ApiKeyResolver, api_key

__all__ = [
    "API_KEY_PREFIX",
    "ERROR_CODES",
    "ApiKeyListOut",
    "ApiKeyResolver",
    "CreateApiKeyIn",
    "ListApiKeysIn",
    "UpdateApiKeyIn",
    "api_key",
]
