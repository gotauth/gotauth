"""The GotAuth core: assembly, request pipeline and core services (work package C1).

::

    from gotauth import GotAuth
    from gotauth.storage.memory import memory_adapter

    auth = GotAuth(
        database=memory_adapter(),
        secret="a-secret-of-at-least-32-characters-...",
        base_url="https://api.example.com",
    )
    app.mount("/api/auth", auth.asgi())
"""

from __future__ import annotations

from gotauth.contracts.protection import resolve_client_ip, validate_redirect
from gotauth.core._asgi import MAX_BODY_BYTES
from gotauth.core._auth import GotAuth
from gotauth.core._context import RequestContext
from gotauth.core._http import OAUTH_ERROR_MAP

__all__ = [
    "MAX_BODY_BYTES",
    "OAUTH_ERROR_MAP",
    "GotAuth",
    "RequestContext",
    "resolve_client_ip",
    "validate_redirect",
]
