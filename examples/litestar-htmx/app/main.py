"""Server-rendered pages. Every change (sign-in, sign-out, keys) goes from htmx
straight to GotAuth's JSON endpoints, which check the Origin header; the app's own
routes only read."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from litestar import Litestar, Request, get
from litestar.di import NamedDependency
from litestar.plugins.jinja import JinjaTemplateEngine
from litestar.response import Redirect, Template
from litestar.static_files import create_static_files_router
from litestar.template.config import TemplateConfig

from gotauth import GotAuth, Principal
from gotauth.integrations.asgi.litestar import GotAuthPlugin

from .auth import SCOPES

HERE = Path(__file__).parent


def create_app(auth: GotAuth) -> Litestar:
    async def as_user(
        request: Request[Any, Any, Any], endpoint: str
    ) -> Any:  # Any: output
        """Call a GotAuth endpoint on the server, as the browser's user (its cookie)."""
        return await auth.api.call(
            endpoint, headers={"cookie": request.headers.get("cookie", "")}
        )

    async def signed_in(
        request: Request[Any, Any, Any], principal: Principal | None
    ) -> Any:  # Any: SessionWithUserOut or None
        # Taking `principal` (GotAuthPlugin) also renews an active session's cookie.
        if principal is None or principal.via != "session":
            return None
        return await as_user(request, "get_session")

    @get("/")
    async def home(
        request: Request[Any, Any, Any], principal: NamedDependency[Principal | None]
    ) -> Template:
        session = await signed_in(request, principal)
        return Template("home.html", context={"session": session})

    @get("/sign-in")
    async def sign_in() -> Template:
        return Template("sign_in.html")

    @get("/sign-up")
    async def sign_up() -> Template:
        return Template("sign_up.html")

    @get("/keys")
    async def keys(
        request: Request[Any, Any, Any], principal: NamedDependency[Principal | None]
    ) -> Template | Redirect:
        session = await signed_in(request, principal)
        if session is None:
            return Redirect("/sign-in")
        return Template("keys.html", context={"session": session, "scopes": SCOPES})

    @get("/keys/list")
    async def key_list(request: Request[Any, Any, Any]) -> Template:
        """The table only, reloaded by htmx after a key is created or deleted."""
        listed = await as_user(request, "list_api_keys")
        return Template("_keys.html", context={"keys": listed.api_keys})

    return Litestar(
        route_handlers=[
            home,
            sign_in,
            sign_up,
            keys,
            key_list,
            create_static_files_router(path="/static", directories=[HERE / "static"]),
        ],
        plugins=[GotAuthPlugin(auth)],
        template_config=TemplateConfig(
            directory=HERE / "templates", engine=JinjaTemplateEngine
        ),
    )


def _default_app() -> Litestar:
    from .auth import auth  # reads the environment

    return create_app(auth)


app = _default_app()
