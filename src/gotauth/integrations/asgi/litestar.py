"""Litestar integration (work package A2). Needs ``pip install "gotauth[litestar]"``.

Example::

    from litestar import Litestar, get
    from litestar.di import NamedDependency

    from gotauth import User
    from gotauth.integrations.asgi.litestar import GotAuthPlugin, requires_scopes

    @get("/projects", guards=[requires_scopes("projects:read")])
    async def projects(current_user: NamedDependency[User]) -> dict[str, str]:
        return {"user": current_user.id}

    app = Litestar(route_handlers=[projects], plugins=[GotAuthPlugin(auth)])
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any, cast

from litestar import Request, Response, asgi
from litestar.config.app import AppConfig
from litestar.connection import ASGIConnection
from litestar.di import Provide
from litestar.handlers.base import BaseRouteHandler
from litestar.plugins import InitPluginProtocol

from gotauth.contracts.core_schema import User
from gotauth.contracts.errors import AuthError
from gotauth.contracts.http_models import SessionWithUserOut
from gotauth.contracts.principal import Principal
from gotauth.integrations.asgi._common import (
    error_payload,
    headers_from,
    missing_scopes,
    resolve,
)

if TYPE_CHECKING:
    from gotauth.contracts.config import GotAuthInstance as GotAuth

__all__ = ["GotAuthPlugin", "requires_scopes", "requires_session"]

Guard = Callable[
    [ASGIConnection[Any, Any, Any, Any], BaseRouteHandler], Coroutine[Any, Any, None]
]

_STATE_KEY = "gotauth_principal"


def _auth_of(connection: ASGIConnection[Any, Any, Any, Any]) -> GotAuth:
    auth = connection.app.state.get("gotauth")
    if auth is None:
        msg = "add GotAuthPlugin(auth) to the Litestar app"
        raise RuntimeError(msg)
    return auth  # type: ignore[no-any-return]


async def _principal(
    connection: ASGIConnection[Any, Any, Any, Any],
) -> Principal | None:
    """The principal, resolved once per connection."""
    scope = cast(dict[str, Any], connection.scope)
    state = cast(dict[str, Any], scope.setdefault("state", {}))
    if _STATE_KEY not in state:
        headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
        state[_STATE_KEY] = await resolve(_auth_of(connection), headers)
    return cast(Principal | None, state[_STATE_KEY])


async def requires_session(
    connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
) -> None:
    """Guard: a signed-in session (cookie or ``Bearer gas_...``), else 401."""
    principal = await _principal(connection)
    if principal is None or principal.via != "session":
        raise AuthError("UNAUTHENTICATED", 401)


def requires_scopes(*scopes: str) -> Guard:
    """Guard: 401 without a principal, 403 ``INSUFFICIENT_SCOPE`` when a key or token
    lacks a scope. Sessions have full rights and pass."""
    wanted = tuple(scopes)

    async def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
    ) -> None:
        principal = await _principal(connection)
        if principal is None:
            raise AuthError("UNAUTHENTICATED", 401)
        missing = missing_scopes(principal, wanted)
        if missing:
            raise AuthError("INSUFFICIENT_SCOPE", 403, None, {"required": missing})

    return guard


async def _provide_principal(request: Request[Any, Any, Any]) -> Principal | None:
    return await _principal(request)


async def _provide_current_user(request: Request[Any, Any, Any]) -> User:
    auth = _auth_of(request)
    scope = cast(dict[str, Any], request.scope)
    headers = headers_from(cast(list[tuple[bytes, bytes]], scope.get("headers", [])))
    forwarded = {k: v for k, v in headers.items() if k in ("cookie", "authorization")}
    try:
        found = await auth.api.call("get_session", headers=forwarded)
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError("INTERNAL_ERROR", 500) from exc
    if found is None:
        raise AuthError("UNAUTHENTICATED", 401)
    session = (
        found
        if isinstance(found, SessionWithUserOut)
        else SessionWithUserOut.model_validate(found)
    )
    return session.user


def _handle_auth_error(_: Request[Any, Any, Any], exc: AuthError) -> Response[bytes]:
    status, payload, headers = error_payload(exc)
    return Response(content=payload, status_code=status, headers=headers)


class GotAuthPlugin(InitPluginProtocol):
    """Mounts GotAuth and adds the ``principal`` and ``current_user`` dependencies and
    the ``AuthError`` handler."""

    def __init__(self, auth: GotAuth) -> None:
        self._auth = auth

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        auth = self._auth
        auth_app = auth.asgi()
        well_known_app = auth.well_known()

        def original(scope: Any) -> Any:  # Any: an ASGI scope
            # Litestar strips the mount prefix and adds a trailing slash; GotAuth needs
            # the request's own path, which raw_path keeps.
            raw = scope.get("raw_path")
            path = raw.decode("latin-1") if isinstance(raw, bytes) else scope["path"]
            return {**scope, "path": path, "root_path": ""}

        @asgi(
            path=auth.config.base_path.rstrip("/") or "/",
            is_mount=True,
            copy_scope=True,
        )
        async def gotauth(scope: Any, receive: Any, send: Any) -> None:  # Any: ASGI
            await auth_app(original(scope), receive, send)

        # At "/.well-known", not "/": a Litestar mount at "/" takes every request,
        # app routes included. Every GotAuth well-known document lives below it.
        @asgi(path="/.well-known", is_mount=True, copy_scope=True)
        async def gotauth_well_known(scope: Any, receive: Any, send: Any) -> None:
            await well_known_app(original(scope), receive, send)

        app_config.route_handlers.extend([gotauth, gotauth_well_known])
        app_config.dependencies.update(
            {
                "principal": Provide(_provide_principal),
                "current_user": Provide(_provide_current_user),
            }
        )
        handlers = cast(
            dict[Any, Any],
            app_config.exception_handlers,  # pyright: ignore[reportUnknownMemberType]
        )
        handlers[AuthError] = _handle_auth_error
        app_config.state["gotauth"] = auth
        app_config.signature_namespace.update({"Principal": Principal, "User": User})
        return app_config
