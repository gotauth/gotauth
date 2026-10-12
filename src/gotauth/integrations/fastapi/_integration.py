# ruff: noqa: I002 - no __future__ import: FastAPI must see real annotations
"""FastAPI routes, dependencies and exception handlers over GotAuth (work package A1).

No ``from __future__ import annotations`` here: FastAPI reads the annotations of the
generated route functions and dependencies at runtime.
"""

import inspect
import re
from collections.abc import (
    AsyncGenerator,
    Awaitable,
    Callable,
    Coroutine,
    Mapping,
    Sequence,
)
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated, Any, cast
from urllib.parse import parse_qsl

from fastapi import (
    APIRouter,
    Body,
    Depends,
    FastAPI,
    Form,
    Path,
    Query,
    Request,
    Response,
)
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from pydantic import BaseModel

from gotauth.contracts.core_schema import User
from gotauth.contracts.endpoints import Endpoint
from gotauth.contracts.errors import AuthError, ConfigError, ErrorOut
from gotauth.contracts.http import AuthRequest, AuthResponse
from gotauth.contracts.http_models import SessionWithUserOut
from gotauth.contracts.principal import Principal
from gotauth.contracts.protection import resolve_client_ip
from gotauth.contracts.sessions import SessionWithUser
from gotauth.core._http import (
    body_bytes,
    error_response,
    input_format,
    set_cookie_header,
)

if TYPE_CHECKING:
    from gotauth.core import GotAuth

__all__ = ["FastAPIIntegration", "OAuthErrorOut"]

MAX_BODY_BYTES = 1024 * 1024
_PARAM = re.compile(r"\{(\w+)\}")
# request.state attribute holding the principal resolved for this request.
_PRINCIPAL_STATE = "gotauth_principal"


class OAuthErrorOut(BaseModel):
    """RFC 6749 error body, used by endpoints with ``error_format="oauth"``."""

    error: str
    error_description: str | None = None


def _cookies(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in header.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            cookies.setdefault(name, value)
    return cookies


def _headers(request: Request) -> dict[str, str]:
    """Request headers with repeats joined, as the core's ASGI app does: cookies with
    "; " (HTTP/2 may split them), everything else with ", "."""
    headers: dict[str, str] = {}
    for raw_name, raw_value in request.scope.get("headers", []):
        name = bytes(raw_name).decode("latin-1").lower()
        value = bytes(raw_value).decode("latin-1")
        if name in headers:
            separator = "; " if name == "cookie" else ", "
            headers[name] = f"{headers[name]}{separator}{value}"
        else:
            headers[name] = value
    return headers


def _to_starlette(response: AuthResponse) -> Response:
    """Turn a GotAuth response into a Starlette one: JSON, HTML or a redirect."""
    status = response.status
    headers: dict[str, str] = {}
    if response.redirect is not None:
        status = 302 if status == 200 else status
        out = Response(status_code=status)
        out.headers["location"] = response.redirect
    else:
        payload, content_type = body_bytes(response)
        out = Response(content=payload, status_code=status, media_type=content_type)
    for name, value in response.headers.items():
        headers[name.lower()] = value
    for name, value in headers.items():
        out.headers[name] = value
    for cookie in response.cookies:
        out.raw_headers.append(
            (b"set-cookie", set_cookie_header(cookie).encode("latin-1"))
        )
    return out


def _error(error: AuthError) -> Response:
    response = error_response(error, "gotauth")
    if error.status == 401:
        response.headers.setdefault("www-authenticate", "Bearer")
    return _to_starlette(response)


class FastAPIIntegration:
    """``auth.fastapi``: the router, dependencies and exception handlers.

    Usage::

        app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
        auth.fastapi.add_exception_handlers(app)
        CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]
    """

    # Quoted: GotAuth is imported for type checking only, and this module has no
    # `from __future__ import annotations`, so Python before 3.14 evaluates it.
    def __init__(self, auth: "GotAuth") -> None:
        self._auth = auth

    # ------------------------------------------------------------ router

    def router(self) -> APIRouter:
        """One route per HTTP endpoint (``server_only`` ones excluded).

        Include it with ``prefix=auth.config.base_path``.
        """
        integration = self

        class GotAuthRoute(APIRoute):
            """Uses the models for OpenAPI only; the raw request goes to GotAuth, so
            content types, validation (400, never 422) and forms stay in the core."""

            def get_route_handler(
                self,
            ) -> Callable[[Request], Coroutine[Any, Any, Response]]:
                async def handler(request: Request) -> Response:
                    return await integration.dispatch(request)

                return handler

        @asynccontextmanager
        async def lifespan(_: Any) -> AsyncGenerator[None]:  # Any: the app
            yield
            await self._auth.drain()  # background email and event deliveries

        router = APIRouter(route_class=GotAuthRoute, lifespan=lifespan)
        for endpoint in self._endpoints():
            self._add_route(router, endpoint)
        return router

    def _endpoints(self) -> list[Endpoint[Any, Any]]:
        return [
            endpoint
            for plugin in self._auth.plugins
            for endpoint in plugin.endpoints
            if not endpoint.server_only
        ]

    def _add_route(self, router: APIRouter, endpoint: Endpoint[Any, Any]) -> None:
        parameters: list[inspect.Parameter] = [
            inspect.Parameter(
                name, inspect.Parameter.KEYWORD_ONLY, annotation=Annotated[str, Path()]
            )
            for name in _PARAM.findall(endpoint.path)
        ]
        if endpoint.input is not None:
            marker: Any  # Any: a FastAPI parameter marker
            match input_format(endpoint):
                case "query":
                    marker = Query()
                case "form":
                    marker = Form()
                case _:
                    marker = Body()
            parameters.append(
                inspect.Parameter(
                    "data",
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=Annotated[endpoint.input, marker],
                )
            )

        async def route(**_: Any) -> None:  # never called: GotAuthRoute replaces it
            raise RuntimeError("unreachable")

        route.__signature__ = inspect.Signature(parameters)  # type: ignore[attr-defined]
        route.__name__ = endpoint.id
        error_model: type[BaseModel] = (
            OAuthErrorOut if endpoint.error_format == "oauth" else ErrorOut
        )
        responses: dict[int | str, dict[str, Any]] = {
            # "4XX" also stops FastAPI from documenting its own 422: GotAuth answers
            # validation errors with 400 INVALID_REQUEST.
            "4XX": {"model": error_model, "description": "Error"},
        }
        response_model: Any = endpoint.output
        if endpoint.id == "get_session" and endpoint.output is not None:
            response_model = endpoint.output | None  # null when signed out
        if endpoint.output is None:
            responses[302] = {"description": "Redirect"}
        router.add_api_route(
            endpoint.path,
            route,
            methods=[endpoint.method],
            operation_id=endpoint.id,
            summary=endpoint.summary or None,
            tags=list(endpoint.tags) or None,
            response_model=response_model,
            responses=responses,
            name=endpoint.id,
        )

    # ------------------------------------------------------------ dispatch

    async def dispatch(self, request: Request) -> Response:
        """Hand one request to ``auth.handle`` and render its answer."""
        config = self._auth.config
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BODY_BYTES:
                return _to_starlette(
                    error_response(
                        AuthError("INVALID_REQUEST", 413, "Body is too large"),
                        "gotauth",
                    )
                )
        root = request.scope.get("root_path", "") or ""
        path = request.url.path
        if root and path.startswith(root):
            path = path[len(root) :] or "/"
        base = config.base_path.rstrip("/")
        if base:
            if path != base and not path.startswith(base + "/"):
                msg = (
                    f"include the GotAuth router with prefix={base!r} "
                    f"(the request path {path!r} is outside base_path)"
                )
                raise ConfigError(msg)
            path = path[len(base) :] or "/"
        headers = _headers(request)
        query_string = request.url.query
        peer = request.client.host if request.client else None
        auth_request = AuthRequest(
            method=request.method.upper(),
            path=path,
            url=config.base_url
            + base
            + path
            + (f"?{query_string}" if query_string else ""),
            query=dict(parse_qsl(query_string, keep_blank_values=True)),
            headers=headers,
            cookies=_cookies(headers.get("cookie", "")),
            body=body,
            client_ip=resolve_client_ip(peer, headers, config),
        )
        return _to_starlette(await self._auth.handle(auth_request))

    def check_app(self, app: FastAPI) -> None:
        """Raise ``ConfigError`` unless the router is included at ``base_path``.

        Reads the app's OpenAPI document, whose paths carry the include prefix.
        """
        base = self._auth.config.base_path.rstrip("/")
        found: dict[str, str] = {}
        # get_openapi, not app.openapi(): that caches the schema on the app, and routes
        # added after this check would then be missing from /docs.
        schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
        paths = cast(dict[str, dict[str, Any]], schema.get("paths", {}))
        for path, operations in paths.items():
            for operation in operations.values():
                if isinstance(operation, dict):
                    operation_id = cast(dict[str, Any], operation).get("operationId")
                    if operation_id is not None:
                        found[str(operation_id)] = path
        endpoints = self._endpoints()
        if not any(endpoint.id in found for endpoint in endpoints):
            raise ConfigError("the GotAuth router is not included in this app")
        for endpoint in endpoints:
            path = found.get(endpoint.id)
            if path is not None and path != base + endpoint.path:
                msg = f"include the GotAuth router with prefix={base!r}"
                raise ConfigError(msg)

    # ------------------------------------------------------------ errors

    def add_exception_handlers(self, app: FastAPI) -> None:
        """Render ``AuthError`` (from dependencies and your routes) as GotAuth JSON."""

        async def handle(_: Request, exc: Exception) -> Response:
            return _error(cast(AuthError, exc))

        app.add_exception_handler(AuthError, handle)

    # ------------------------------------------------------------ dependencies

    @staticmethod
    def _credentials(request: Request) -> tuple[dict[str, str], dict[str, str]]:
        headers = _headers(request)
        return headers, _cookies(headers.get("cookie", ""))

    async def _session(
        self, request: Request, response: Response
    ) -> SessionWithUser | None:
        headers, _ = self._credentials(request)
        forwarded = {
            key: value
            for key, value in headers.items()
            if key in ("cookie", "authorization", "user-agent")
        }
        try:
            result = await self._auth.api.call(
                "get_session", headers=forwarded, as_response=True
            )
        except AuthError:
            raise
        except Exception as exc:
            raise AuthError("INTERNAL_ERROR", 500) from exc
        out = cast(AuthResponse, result)
        for cookie in out.cookies:  # a sliding refresh re-sets the cookie
            response.raw_headers.append(
                (b"set-cookie", set_cookie_header(cookie).encode("latin-1"))
            )
        body = out.body
        if body is None:
            return None
        try:
            found = (
                body
                if isinstance(body, SessionWithUserOut)
                else SessionWithUserOut.model_validate(body)
            )
        except Exception as exc:
            raise AuthError("INTERNAL_ERROR", 500) from exc
        return SessionWithUser(session=found.session, user=found.user)

    async def current_session(
        self, request: Request, response: Response
    ) -> SessionWithUser:
        """The session and its user; 401 without one."""
        found = await self._session(request, response)
        if found is None:
            raise AuthError("UNAUTHENTICATED", 401)
        return found

    async def current_user(self, request: Request, response: Response) -> User:
        """The signed-in user (session cookie or ``Bearer gas_...``); 401 otherwise."""
        return (await self.current_session(request, response)).user

    async def optional_user(self, request: Request, response: Response) -> User | None:
        """The signed-in user, or ``None``: a bad or rejected credential counts as
        signed out, never a 401."""
        try:
            found = await self._session(request, response)
        except AuthError as error:
            if error.status in (401, 403):
                return None
            raise
        return found.user if found is not None else None

    async def current_principal(self, request: Request) -> Principal:
        """Whoever the request acts for: session, API key or OAuth token; 401 otherwise.

        Principal checks run, so a plugin can reject (for example banned users).
        Resolved once per request, however many dependencies ask: each lookup of an
        API key counts against its rate limit.
        """
        cached = getattr(request.state, _PRINCIPAL_STATE, None)
        if isinstance(cached, Principal):
            return cached
        headers, cookies = self._credentials(request)
        try:
            principal = await self._auth.get_principal(headers, cookies)
        except AuthError:
            raise
        except Exception as exc:
            raise AuthError("INTERNAL_ERROR", 500) from exc
        if principal is None:
            raise AuthError("UNAUTHENTICATED", 401)
        setattr(request.state, _PRINCIPAL_STATE, principal)
        return principal

    async def api_key_principal(self, request: Request) -> Principal:
        """A principal from an API key only; 401 for sessions and OAuth tokens."""
        principal = await self.current_principal(request)
        if principal.via != "api_key":
            raise AuthError("UNAUTHENTICATED", 401, "An API key is required")
        return principal

    def require(
        self, *scopes: str, permission: Mapping[str, Sequence[str]] | None = None
    ) -> Callable[..., Awaitable[Principal]]:
        """A dependency returning the principal when it has every scope (and, with
        ``permission``, the organization permission from the organization plugin).

        Raises:
            ConfigError: ``permission`` without the organization plugin.
        """
        if permission is not None and "organization" not in self._auth.plugin_ids:
            msg = "require(permission=...) needs the organization plugin"
            raise ConfigError(msg)
        wanted = tuple(scopes)
        integration = self

        async def dependency(
            request: Request,
            principal: Annotated[Principal, Depends(integration.current_principal)],
        ) -> Principal:
            if not principal.has_scopes(*wanted):
                missing = sorted(set(wanted) - (principal.scopes or set()))
                raise AuthError("INSUFFICIENT_SCOPE", 403, None, {"required": missing})
            if permission is not None:
                headers, _ = integration._credentials(request)
                forwarded = {
                    key: value
                    for key, value in headers.items()
                    if key in ("cookie", "authorization", "x-api-key")
                }
                try:
                    result = await integration._auth.api.call(
                        "has_permission",
                        body={
                            "permissions": {
                                key: list(value) for key, value in permission.items()
                            }
                        },
                        headers=forwarded,
                    )
                except AuthError:
                    raise
                except Exception as exc:
                    raise AuthError("INTERNAL_ERROR", 500) from exc
                if not getattr(result, "success", False):
                    raise AuthError("FORBIDDEN", 403)
            return principal

        return dependency
