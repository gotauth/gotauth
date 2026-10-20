# r/FastAPI

**Rules:** read the sidebar on the day (Reddit blocked automated reads on 2026-10-16).

## Title

GotAuth: auth for FastAPI that lives in your database, with API keys, passkeys, orgs and an OAuth server for MCP

## Post

I've been building GotAuth, an open-source (MIT) auth library for FastAPI. It runs
inside your app, keeps users in your own database, and puts every endpoint in your
OpenAPI schema.

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from gotauth import GotAuth, User

auth = GotAuth(database=..., secret=..., base_url="https://api.example.com")
app = FastAPI()
app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
auth.fastapi.add_exception_handlers(app)

CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]


@app.get("/projects")
async def projects(user: CurrentUser) -> list[str]: ...
```

**What is in it:**

- Email and password with verification and reset, sessions (opaque tokens, hashed at
  rest, cookie or bearer), social login (GitHub, Google, Microsoft, Apple, Discord,
  GitLab, generic OIDC).
- Plugins: two-factor (TOTP, backup codes, email codes), passkeys, magic links and
  email codes, organizations with roles and invitations, admin (bans, impersonation),
  API keys with scopes.
- `auth.fastapi.require("projects:read")` works the same for a session, an API key or
  an OAuth token.
- An OAuth 2.1 / OpenID provider, which is also what an MCP server needs to let Claude
  or other MCP clients sign users in (see `examples/fastmcp-server`).
- SQLAlchemy 2 async on Postgres or SQLite, with Alembic revisions from
  `gotauth generate`. Tables are prefixed `auth_`, so they don't clash with your
  `user` table.
- Starlette and Litestar work too.

**Coming from fastapi-users?** It has been in maintenance mode since October 2025 (its
maintainer's announcement), and still gets security fixes. GotAuth has an importer that
keeps user ids and password hashes, so nobody resets a password:

```bash
gotauth import fastapi-users --auth app.auth:auth --dry-run --report dry-run.json
```

The [migration guide](https://github.com/gotauth/gotauth/blob/main/src/gotauth/importers/fastapi_users/README.md)
maps the fastapi-users API to GotAuth's.

**Also useful without GotAuth:** `uvx gotauth check` scans a project for risky
hand-written auth (passlib, python-jose, HS256 with a literal secret, `==` on tokens,
`verify=False` and more), with `ast` only and no network.

**Not done yet:** 0.1, pre-1.0, one maintainer; no Flask or Django adapter; no SAML or
SCIM. The comparison page lists when another option is the better choice.

Repo: https://github.com/gotauth/gotauth
Example app (FastAPI + Next.js): `examples/fastapi-nextjs`

Feedback on the API is the most useful thing right now.
