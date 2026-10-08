"""Starlette integration (work package A2). Needs ``pip install "gotauth[starlette]"``.

Example::

    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.routing import Mount, Route

    from gotauth.integrations.asgi.starlette import gotauth_middleware, requires_scopes

    @requires_scopes("projects:read")
    async def projects(request):
        return JSONResponse({"user": request.user.identity})

    app = Starlette(
        routes=[
            Route("/projects", projects),
            Mount(auth.config.base_path, app=auth.asgi()),
            Mount("/", app=auth.well_known()),  # last, so your routes keep priority
        ],
        middleware=[gotauth_middleware(auth)],
    )
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, TypeVar, cast

from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    BaseUser,
)
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection
from starlette.responses import Response
from starlette.websockets import WebSocket

from gotauth.contracts.errors import AuthError
from gotauth.contracts.principal import Principal
from gotauth.integrations.asgi._common import error_payload, missing_scopes, resolve

if TYPE_CHECKING:
    from gotauth.contracts.config import GotAuthInstance as GotAuth

__all__ = [
    "GotAuthBackend",
    "GotAuthUser",
    "gotauth_middleware",
    "on_error",
    "requires_scopes",
]

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


class GotAuthUser(BaseUser):
    """``request.user`` for a resolved principal."""

    def __init__(self, principal: Principal) -> None:
        self.principal = principal

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def user_id(self) -> str | None:
        """The human the request acts for (``None`` for organization keys)."""
        return self.principal.user_id

    @property
    def identity(self) -> str:
        """User id, else agent id, else the credential id."""
        principal = self.principal
        return principal.user_id or principal.agent_id or principal.credential_id

    @property
    def display_name(self) -> str:
        return self.identity


class _GotAuthFailure(AuthenticationError):
    """Carries the GotAuth error to ``on_error``."""

    def __init__(self, error: AuthError) -> None:
        super().__init__(error.code)
        self.error = error


class GotAuthBackend(AuthenticationBackend):
    """Resolves the principal with ``auth.get_principal`` for HTTP and WebSockets.

    No credential: Starlette's anonymous user. A bad credential: ``on_error`` answers
    with the GotAuth error. An unexpected failure: 500 ``INTERNAL_ERROR``, never a user.
    """

    def __init__(self, auth: GotAuth) -> None:
        self._auth = auth

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, BaseUser] | None:
        try:
            principal = await resolve(self._auth, conn.scope.get("headers", []))
        except AuthError as error:
            raise _GotAuthFailure(error) from error
        if principal is None:
            return None
        scopes = ["authenticated"]
        if principal.via == "session":
            scopes.append("session")
        scopes.extend(sorted(principal.scopes or ()))
        return AuthCredentials(scopes), GotAuthUser(principal)


def on_error(conn: HTTPConnection, exc: AuthenticationError) -> Response:
    """Render authentication failures in GotAuth's error shape."""
    error = (
        exc.error
        if isinstance(exc, _GotAuthFailure)
        else AuthError("UNAUTHENTICATED", 401)
    )
    status, payload, headers = error_payload(error)
    return Response(content=payload, status_code=status, headers=headers)


def gotauth_middleware(auth: GotAuth) -> Middleware:
    """``AuthenticationMiddleware`` with the GotAuth backend and error handler."""
    return Middleware(
        AuthenticationMiddleware, backend=GotAuthBackend(auth), on_error=on_error
    )


def _error_response(error: AuthError) -> Response:
    status, payload, headers = error_payload(error)
    return Response(content=payload, status_code=status, headers=headers)


def requires_scopes(*scopes: str) -> Callable[[F], F]:
    """Guard an endpoint: 401 without a principal, 403 ``INSUFFICIENT_SCOPE`` (with
    ``details.required``) when a key or token lacks a scope. Sessions pass: they have
    full rights, which Starlette's own ``@requires`` cannot express."""
    wanted = tuple(scopes)

    def decorate(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:  # Any: endpoint args
            conn: HTTPConnection[Any] | None = None
            for candidate in (*args, *kwargs.values()):
                if isinstance(candidate, HTTPConnection):
                    conn = cast("HTTPConnection[Any]", candidate)
                    break
            if conn is None:
                msg = "requires_scopes needs a Request or WebSocket argument"
                raise TypeError(msg)
            user = conn.user if "user" in conn.scope else None
            if not isinstance(user, GotAuthUser):
                error = AuthError("UNAUTHENTICATED", 401)
            else:
                missing = missing_scopes(user.principal, wanted)
                error = (
                    AuthError("INSUFFICIENT_SCOPE", 403, None, {"required": missing})
                    if missing
                    else None
                )
            if error is not None:
                if isinstance(conn, WebSocket):
                    await conn.close(code=1008)
                    return None
                return _error_response(error)
            return await func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate
