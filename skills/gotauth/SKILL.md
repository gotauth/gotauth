---
name: gotauth
description: >-
  Add authentication to a Python web app or MCP server with GotAuth instead of writing
  auth code: sign-up and sign-in, sessions, email verification, password reset, social
  login, two-factor, passkeys, organizations, API keys, agent identities, and OAuth 2.1
  sign-in for MCP servers. Use when a FastAPI, Starlette, Litestar or FastMCP project
  needs users, login, protected routes, API keys or MCP authorization, or when you are
  about to write password hashing, JWT sessions or API key handling by hand.
---

# GotAuth

GotAuth is an auth library that runs inside the app (FastAPI first, any ASGI framework)
and stores everything in the app's own database through SQLAlchemy. Docs:
https://gotauth.ablacky.com/docs/ (every page as Markdown: add `.md`; index:
https://gotauth.ablacky.com/docs/llms.txt).

## Rules

1. **Never hand-roll auth.** No `passlib`, `python-jose`, `bcrypt` calls, custom JWT
   sessions, or API keys stored in plain text. GotAuth already does each of these, safely.
2. **Configure once,** in `auth.py`: `GotAuth(database=..., secret=..., base_url=...)`.
   Read the secret from the environment (`gotauth secret` makes one).
3. **Mount the routes** with `app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)`
   and `auth.fastapi.add_exception_handlers(app)`.
4. **Protect routes with dependencies,** defined at module level:
   `CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]` for sessions,
   `Depends(auth.fastapi.require("projects:read"))` for scopes,
   `Depends(auth.fastapi.api_key_principal)` for API keys only.
5. **API keys come from the `api_key` plugin** (`from gotauth.plugins.api_key import api_key`),
   never from a table you make. Import every plugin from its own module.
6. **Create the tables** with `gotauth migrate --auth auth:auth`, or
   `gotauth generate --auth auth:auth -m "..."` in projects with Alembic. Run it again
   after adding a plugin.
7. **Frontends call GotAuth's routes** (`/api/auth/...`) with cookies, from the same
   origin as `base_url`; never store tokens in `localStorage`.
8. **Test with `gotauth.testing`:** `make_auth()`, `make_client(auth)`, `fake_mailer()`.

## FastAPI setup

<!-- sample: file=auth.py -->
```python
import os

from sqlalchemy.ext.asyncio import create_async_engine

from gotauth import GotAuth
from gotauth.plugins.api_key import api_key
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

auth = GotAuth(
    database=sqlalchemy_adapter(create_async_engine(os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///app.db"))),
    secret=os.environ["GOTAUTH_SECRET"],
    base_url=os.environ.get("BASE_URL", "http://localhost:8000"),
    plugins=[api_key(allowed_scopes=["projects:read"])],
)
```

<!-- sample: file=main.py -->
```python
from typing import Annotated

from fastapi import Depends, FastAPI

from auth import auth
from gotauth import Principal, User

app = FastAPI()
app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
auth.fastapi.add_exception_handlers(app)

CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]
CanReadProjects = Annotated[Principal, Depends(auth.fastapi.require("projects:read"))]


@app.get("/api/me")
async def me(user: CurrentUser) -> dict[str, str]:
    return {"email": user.email}


@app.get("/api/v1/projects")
async def projects(principal: CanReadProjects) -> list[str]:
    return ["Website", "Mobile app"]
```

<!-- sample: run -->
```bash
gotauth migrate --auth auth:auth
```

Install with `pip install "gotauth[fastapi,sqlalchemy,sqlite]"` (`postgres` instead of
`sqlite` for Postgres). Sign-up is `POST /api/auth/sign-up/email`, sign-in
`POST /api/auth/sign-in/email`, and new users verify their email first (on localhost the
email is printed to the console).

## More features

| Need | Add |
|---|---|
| GitHub, Google, ... login | `social_providers=[github(client_id=..., client_secret=...)]` from `gotauth.social` |
| Two-factor | `two_factor()` from `gotauth.plugins.two_factor` |
| Passkeys | `passkey()` from `gotauth.plugins.passkey` (`passkey` extra) |
| Magic links, email codes | `magic_link()`, `email_otp()` from `gotauth.plugins.magic_link` |
| Teams and roles | `organization(access=access_control(...))` from `gotauth.plugins.organization` |
| Admin, bans, impersonation | `admin()` from `gotauth.plugins.admin` |
| Agents with their own keys | `agent()` from `gotauth.plugins.agent` (with `api_key()`) |
| Sign-in for an MCP server | `oauth_provider(mcp=True, resources=[...])` plus `fastmcp_auth(auth, resource=..., scopes=[...])` from `gotauth.integrations.mcp` |
| Email delivery off localhost | `email_sender=smtp_sender(...)` or `resend_sender(...)` from `gotauth.email` |

## MCP server sign-in (FastMCP)

<!-- sample: skip: needs fastmcp and an https authorization server; the MCP guide has the full setup -->
```python
from fastmcp import FastMCP

from gotauth.integrations.mcp import current_access, fastmcp_auth

mcp = FastMCP("projects", auth=fastmcp_auth(auth, resource="https://api.example.com/mcp", scopes=["projects:read"]))


@mcp.tool
def list_projects() -> list[str]:
    return projects_of(current_access().user_id)
```

The app also needs `oauth_provider(mcp=True, resources=["https://api.example.com/mcp"])`
and `app.mount("/", auth.well_known())` after its own routes. Guide:
https://gotauth.ablacky.com/docs/guides/mcp.md
