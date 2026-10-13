# FastAPI reads these annotations at runtime, and they use the `auth` argument of
# create_app, so they must not become strings: no `from __future__ import annotations`.
"""The example: GotAuth's sign-in, consent and "Connected apps" pages, and a FastMCP
server in the same process that accepts GotAuth access tokens."""

import html
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import require_scopes
from pydantic import BaseModel

from app.auth import INSPECTOR_REDIRECT, MCP_URL, SCOPES
from gotauth import GotAuth, User
from gotauth.integrations.mcp import current_access, fastmcp_auth

HERE = Path(__file__).parent
INSPECTOR_CLIENT = "MCP Inspector"


class Project(BaseModel):
    id: int
    name: str


# Demo data, kept in memory per user.
_projects: dict[str, list[Project]] = {}


def projects_of(user_id: str) -> list[Project]:
    if user_id not in _projects:
        names = ("Website redesign", "Mobile app", "Data pipeline")
        _projects[user_id] = [Project(id=i + 1, name=n) for i, n in enumerate(names)]
    return _projects[user_id]


def build_mcp(auth: GotAuth) -> FastMCP:
    """The MCP server: every call needs projects:read, creating one projects:write."""
    mcp = FastMCP(
        "projects",
        auth=fastmcp_auth(auth, resource=MCP_URL, scopes=["projects:read"]),
    )

    def user_id() -> str:
        access = current_access()
        if access is None or access.user_id is None:
            # A client_credentials token acts for no user, and the projects are users'.
            raise ToolError("this tool needs a user's token")
        return access.user_id

    @mcp.tool
    def list_projects() -> list[Project]:
        """The signed-in user's projects."""
        return projects_of(user_id())

    @mcp.tool(auth=require_scopes("projects:write"))
    def create_project(name: str) -> Project:
        """Create a project for the signed-in user."""
        projects = projects_of(user_id())
        project = Project(id=len(projects) + 1, name=name)
        projects.append(project)
        return project

    return mcp


async def seed_inspector_client(auth: GotAuth) -> str:
    """A public client with MCP Inspector's loopback redirect. CIMD refuses loopback
    hosts, so local tools need a client registered up front."""
    listed = await auth.api.call("list_oauth_clients", body={})
    for client in listed.clients:
        if client.name == INSPECTOR_CLIENT:
            return str(client.client_id)
    created = await auth.api.call(
        "create_oauth_client",
        body={
            "name": INSPECTOR_CLIENT,
            "type": "public",
            "redirect_uris": [INSPECTOR_REDIRECT],
            "scopes": ["openid", "profile", "email", *SCOPES, "offline_access"],
        },
    )
    return str(created.client.client_id)


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<link rel='stylesheet' href='/static/app.css'>"
        "<script src='/static/app.js' defer></script></head>"
        f"<body><main>{body}</main></body></html>",
        headers={"cache-control": "no-store"},
    )


def create_app(auth: GotAuth) -> FastAPI:
    mcp_app = build_mcp(auth).http_app(
        path="/mcp", stateless_http=True, json_response=True
    )
    well_known = auth.well_known()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.inspector_client_id = await seed_inspector_client(auth)
        print(  # noqa: T201 - shown to the person running the demo
            f"MCP server: {MCP_URL}\n"
            f"MCP Inspector client_id: {app.state.inspector_client_id}"
        )
        async with mcp_app.lifespan(app):
            yield
        await auth.drain()

    app = FastAPI(title="GotAuth fastmcp-server example", lifespan=lifespan)
    app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
    auth.fastapi.add_exception_handlers(app)
    optional_user = Depends(auth.fastapi.optional_user)

    @app.get("/", include_in_schema=False)
    async def home(user: Annotated[User | None, optional_user]) -> HTMLResponse:
        if user is None:
            who = "<p><a href='/sign-in'>Sign in or create an account</a></p>"
        else:
            who = (
                f"<p>Signed in as <strong>{html.escape(user.email)}</strong>.</p>"
                "<p><a href='/connected-apps'>Connected apps</a></p>"
                "<button data-sign-out>Sign out</button>"
            )
        return page(
            "Projects",
            "<h1>Projects</h1>"
            f"{who}<p>MCP server: <code>{html.escape(MCP_URL)}</code></p>",
        )

    @app.get("/sign-in", include_in_schema=False)
    async def sign_in(callback_url: str = "/") -> HTMLResponse:
        callback = html.escape(callback_url, quote=True)
        return page(
            "Sign in",
            "<h1>Sign in</h1>"
            f"<form data-sign-in data-callback='{callback}'>"
            "<label>Email <input name='email' type='email' required "
            "autocomplete='username'></label>"
            "<label>Password <input name='password' type='password' required "
            "minlength='8' autocomplete='current-password'></label>"
            "<button type='submit' name='action' value='sign-in'>Sign in</button>"
            "<button type='submit' name='action' value='sign-up'>Create account"
            "</button><p data-message role='alert'></p></form>",
        )

    @app.get("/connected-apps", include_in_schema=False, response_model=None)
    async def connected_apps(
        request: Request, user: Annotated[User | None, optional_user]
    ) -> HTMLResponse | RedirectResponse:
        if user is None:
            return RedirectResponse("/sign-in?callback_url=/connected-apps", 303)
        listed = await auth.api.call(
            "list_oauth_grants",
            headers={"cookie": request.headers.get("cookie", "")},
        )
        rows = "".join(
            "<li><strong>"
            f"{html.escape(grant.client_name)}</strong> "
            f"<code>{html.escape(' '.join(grant.scopes))}</code> "
            f"<button data-revoke='{html.escape(grant.client_id, quote=True)}'>"
            "Revoke</button></li>"
            for grant in listed.grants
        )
        return page(
            "Connected apps",
            "<h1>Connected apps</h1>"
            "<p>Apps and agents that can use your projects. Revoking one ends its "
            "access at once.</p>"
            f"<ul>{rows or '<li>None yet.</li>'}</ul><p><a href='/'>Back</a></p>",
        )

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    async def root(scope: Any, receive: Any, send: Any) -> None:  # Any: ASGI
        # The MCP server and its RFC 9728 document, else GotAuth's well-known
        # documents (RFC 8414 metadata for the issuer).
        path = str(scope.get("path", ""))
        mcp_paths = path in ("/mcp", "/mcp/") or path.startswith(
            "/.well-known/oauth-protected-resource"
        )
        await (mcp_app if mcp_paths else well_known)(scope, receive, send)

    app.mount("/", root)  # last: FastAPI's own routes come first
    return app


def _default_app() -> FastAPI:
    from app.auth import auth  # reads the environment

    return create_app(auth)


app = _default_app()
