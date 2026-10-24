---
title: Login for your FastMCP server from your own user table
published: false
tags: python, mcp, fastapi, oauth
---

<!-- Every code block below is copied from examples/fastmcp-server, which its own
tests and the end-to-end tests run (fact-check.md says how this was checked). Lines
replaced by "..." are left out of the quote, not changed. -->

An MCP server that real people connect to, from Claude or any other MCP client, needs
OAuth. The client finds out where to sign the user in, the user signs in and consents,
and the client gets a token for your server.

Most guides send you to a hosted identity provider for the sign-in part. This tutorial
keeps the users in your app's own database instead, with
[GotAuth](https://github.com/gotauth/gotauth): it becomes the OAuth 2.1 authorization
server, inside the same FastAPI app as your FastMCP server.

You will end up with:
- a FastMCP server at `/mcp` that accepts only tokens issued for it
- sign-in and consent pages on your own user table
- a tool that needs an extra scope, which the client asks the user for when needed
- revocation that applies on the next call

The finished app is
[`examples/fastmcp-server`](https://github.com/gotauth/gotauth/tree/main/examples/fastmcp-server).
Built with FastMCP 4.1.3, FastAPI 0.143 and Python 3.14, for the MCP authorization
revision 2026-07-28.

## 1. Get the example

The app has two files: `app/auth.py` (all of the auth setup, shown in full below) and
`app/main.py` (the MCP server, the pages and the wiring; this tutorial shows the parts
that matter for auth). Clone it and set a secret:

```bash
git clone https://github.com/gotauth/gotauth
cd gotauth/examples/fastmcp-server
uv sync --locked
echo "GOTAUTH_SECRET=$(uv run gotauth secret)" > .env
set -a && . ./.env && set +a
```

In your own project, the dependencies are
`uv add "gotauth[fastapi,mcp,sqlalchemy,sqlite]" uvicorn`.

## 2. The authorization server

All of the auth configuration is one `GotAuth(...)` call. `oauth_provider(mcp=True)`
turns on the OAuth 2.1 server with the rules MCP needs: PKCE, a `resource` on every
token request, and tokens whose audience is that resource.

`app/auth.py`, complete:

```python
"""All of this app's auth configuration."""

from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import create_async_engine

from gotauth import GotAuth
from gotauth.contracts import Adapter, EmailSender
from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

env = os.environ

BASE_URL = env.get("BASE_URL", "http://localhost:8000").rstrip("/")
"""The public origin: a tunnel URL when a hosted client such as Claude connects."""
MCP_URL = f"{BASE_URL}/mcp"
"""The MCP server's URL, which access tokens must name as their audience."""
SCOPES = ("projects:read", "projects:write")
INSPECTOR_ORIGIN = "http://localhost:6274"
INSPECTOR_REDIRECT = f"{INSPECTOR_ORIGIN}/oauth/callback"
"""MCP Inspector's OAuth callback; the app seeds a public client for it."""


def build_auth(
    database: Adapter | None = None,  # tests pass their own database and mailer
    email_sender: EmailSender | None = None,
) -> GotAuth:
    if database is None:
        url = env.get("DATABASE_URL", "sqlite+aiosqlite:///app.db")
        database = sqlalchemy_adapter(create_async_engine(url))
    return GotAuth(
        database=database,
        secret=env["GOTAUTH_SECRET"],
        base_url=BASE_URL,
        # A demo: sign up and connect at once. Turn this on in a real app.
        email_password={"require_email_verification": False},
        email_sender=email_sender,  # None: printed to the console on localhost
        plugins=[
            oauth_provider(
                mcp=True,
                resources=[MCP_URL],
                scopes=("openid", "profile", "email", *SCOPES, "offline_access"),
                login_page="/sign-in",
                # Claude and other hosted clients register themselves (RFC 7591).
                allow_dynamic_registration=True,
            )
        ],
    )


auth = build_auth()
```

- `database` defaults to SQLite through `sqlalchemy_adapter(create_async_engine(url))`;
  set `DATABASE_URL` for Postgres. GotAuth's tables are named `auth_user`, `auth_session` and so on, so they sit next to
  a `user` table you already have.
- `login_page` is your own sign-in page. The OAuth flow sends the browser there when
  nobody is signed in, with a `callback_url` to return to.
- Clients can also register with a client ID metadata document (CIMD), which the
  2026-07-28 spec revision prefers. That needs no option.

Create the tables once:

```bash
uv run gotauth migrate --auth app.auth:auth
```

## 3. The MCP server

`fastmcp_auth` gives FastMCP a token verifier that accepts only GotAuth access tokens
issued for `MCP_URL`. Tools read the caller with `current_access()`.

```python
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
```

A call to `create_project` with a token that lacks `projects:write` gets an HTTP 403
with `error="insufficient_scope"`, so the client can ask the user for the extra scope
and retry.

## 4. One app for both

GotAuth's routes go under `/api/auth`, the MCP server under `/mcp`, and the discovery
documents under `/.well-known/`. These are the auth-related lines of `create_app` in
`app/main.py`; the file also has the sign-in and "Connected apps" pages, a client
registered for MCP Inspector, and CORS for Inspector's page:

```python
    mcp_app = build_mcp(auth).http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        # FastMCP's DNS-rebinding guard: the public host, also behind a tunnel.
        host_origin_protection=True,
        allowed_hosts=[urlsplit(BASE_URL).netloc],
        allowed_origins=[BASE_URL, INSPECTOR_ORIGIN],
    )
    well_known = auth.well_known()
...
        async with mcp_app.lifespan(app):
            yield
...
    app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
    auth.fastapi.add_exception_handlers(app)
...
    async def root(scope: Any, receive: Any, send: Any) -> None:  # Any: ASGI
        # The MCP server and its RFC 9728 document, else GotAuth's well-known
        # documents (RFC 8414 metadata for the issuer).
        path = str(scope.get("path", ""))
        mcp_paths = path in ("/mcp", "/mcp/") or path.startswith(
            "/.well-known/oauth-protected-resource"
        )
        await (mcp_app if mcp_paths else well_known)(scope, receive, send)

    app.mount("/", root)  # last: FastAPI's own routes come first
```

What a client sees:
1. `POST /mcp` without a token: a 401 whose `WWW-Authenticate` header points to
   `/.well-known/oauth-protected-resource/mcp`.
2. That document names `/api/auth` as the authorization server, and
   `/.well-known/oauth-authorization-server/api/auth` describes it.
3. The client sends the browser to the authorize endpoint with PKCE and
   `resource=<BASE_URL>/mcp`. The user signs in on your page and consents.
4. The client exchanges the code for a token whose audience is your MCP server, and
   calls the tools.

## 5. Try it with MCP Inspector

```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
npx @modelcontextprotocol/inspector
```

In Inspector, pick "Streamable HTTP", enter `http://localhost:8000/mcp`, and in the
authentication settings enter the client id the app printed and the scope
`projects:read projects:write`. Connect: the browser opens the sign-in page, then the
consent page. Then call `list_projects`.

The example registers that client up front because Inspector runs on your machine:
it has no public https URL to serve a client ID metadata document from, and GotAuth
fetches those documents only from public addresses.

## 6. Revoking access

The user's "Connected apps" page calls `POST /api/auth/oauth2/grants/revoke` with the
client id. The MCP server checks tokens in the same process, so the next call is a
401 and the client has to ask the user again. An MCP server on another host that only
checks the JWT sees the revocation when the token expires (10 minutes by default);
turn on introspection there to see it within 5 seconds.

## What's next

- Claude as a client: the example's README shows how to connect it through a tunnel.
- The same `GotAuth` object gives you sessions, social login, two-factor, passkeys,
  organizations and API keys for the rest of your app.
- Docs: https://gotauth.ablacky.com/docs/
