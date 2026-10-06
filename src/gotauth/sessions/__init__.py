"""Sessions, session cookies and bearer session tokens (work package C3).

Tokens are opaque (``gas_...``) and stored only as hashes. See README.md for the
cookie cache and its revocation delay.
"""

from __future__ import annotations

from ._plugin import (
    RevokeSessionIn,
    SessionResolver,
    session_principal,
    sessions_plugin,
)
from ._service import SESSION_PREFIX, DefaultSessionService, session_service
from ._storage import (
    MemorySecondaryStorage,
    RedisSecondaryStorage,
    memory_secondary_storage,
    redis_secondary_storage,
)

__all__ = [
    "SESSION_PREFIX",
    "DefaultSessionService",
    "MemorySecondaryStorage",
    "RedisSecondaryStorage",
    "RevokeSessionIn",
    "SessionResolver",
    "memory_secondary_storage",
    "redis_secondary_storage",
    "session_principal",
    "session_service",
    "sessions_plugin",
]
