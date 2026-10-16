# Quickstart: FastAPI

From an empty FastAPI app to sign-up, email verification, sign-in and a protected route,
with GotAuth storing everything in a SQLite file. Every step uses GotAuth's own APIs: no
password hashing, JWT or session code of your own.

## 1. Install

```bash
pip install "gotauth[fastapi,sqlalchemy,sqlite]" uvicorn
```

With uv: `uv add "gotauth[fastapi,sqlalchemy,sqlite]" uvicorn`. For Postgres, use the
`postgres` extra instead of `sqlite`.

## 2. Configure GotAuth

Create a secret (at least 32 characters) and keep it out of your code:

```bash
echo "GOTAUTH_SECRET=$(gotauth secret)" >> .env
export $(cat .env)
```

`gotauth init` does the same and writes a starter `auth.py`. This is the whole setup,
in `auth.py`:

<!-- sample: file=auth.py -->
```python
import os

from sqlalchemy.ext.asyncio import create_async_engine

from gotauth import GotAuth
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

engine = create_async_engine(os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///app.db"))

auth = GotAuth(
    database=sqlalchemy_adapter(engine),
    secret=os.environ["GOTAUTH_SECRET"],
    base_url=os.environ.get("BASE_URL", "http://localhost:8000"),
)
```

- `base_url` is where users reach your app. Cookies, email links and the allowed
  `Origin` all come from it. On `https`, cookies get the `__Secure-` prefix.
- Email and password sign-up is on by default, and new users must verify their email.
- No email sender is configured, so on `localhost` GotAuth prints each email (with its
  link) to the console. Elsewhere it refuses to start without one: see
  [Email delivery](modules/email.md).

## 3. Add the routes

`main.py` mounts GotAuth's routes at `/api/auth` and protects your own route:

<!-- sample: file=main.py -->
```python
from typing import Annotated

from fastapi import Depends, FastAPI

from auth import auth
from gotauth import User

app = FastAPI()
app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
auth.fastapi.add_exception_handlers(app)

CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]


@app.get("/api/me")
async def me(user: CurrentUser) -> dict[str, str]:
    return {"id": user.id, "email": user.email}
```

`CurrentUser` answers 401 without a session. For routes that also accept API keys or
OAuth tokens, and for scopes, see [Principals and scopes](concepts/principals.md).

## 4. Create the tables

<!-- sample: run -->
```bash
gotauth migrate --auth auth:auth
```

`gotauth migrate` creates missing tables and columns and never drops or changes any.
GotAuth's tables are prefixed with `auth_` (`auth_user`, `auth_session`, ...), so they
sit next to your own. In a project with Alembic, run
`gotauth generate --auth auth:auth -m "gotauth tables"` instead and apply the revision:
see [Schema and migrations](concepts/schema-and-migrations.md).

## 5. Try it

```bash
uvicorn main:app --reload
```

Sign up:

```bash
curl -X POST localhost:8000/api/auth/sign-up/email \
  -H "content-type: application/json" \
  -d '{"email": "ada@example.com", "password": "correct horse battery"}'
```

The answer is `{"status": "verification_sent"}`, whether the address is new or not, so
nobody can probe which emails have accounts. The console shows the email; open its link
to verify the address. Then sign in, keeping the session cookie, and call your route:

```bash
curl -c cookies.txt -X POST localhost:8000/api/auth/sign-in/email \
  -H "content-type: application/json" -H "origin: http://localhost:8000" \
  -d '{"email": "ada@example.com", "password": "correct horse battery"}'
curl -b cookies.txt localhost:8000/api/me
```

`/api/me` answers with the user. Without the cookie it answers 401.

Requests that change something with a session cookie must send an `Origin` header
matching `base_url` (browsers do; curl needs `-H origin`). That is GotAuth's CSRF
protection.

## 6. Test it

The same flow as a test, with httpx and no server. GotAuth prints the email to stderr,
and the test reads the link from there:

<!-- sample: run -->
```python
import asyncio
import contextlib
import io
import re

import httpx

from main import app


async def sign_up_verify_sign_in() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://localhost:8000",
        headers={"origin": "http://localhost:8000"},
    ) as client:
        body = {"email": "ada@example.com", "password": "correct horse battery"}
        console = io.StringIO()
        with contextlib.redirect_stderr(console):
            signed_up = await client.post("/api/auth/sign-up/email", json=body)
        assert signed_up.json() == {"status": "verification_sent"}

        link = re.search(r"http://localhost:8000(/\S+)", console.getvalue())
        assert link, console.getvalue()
        assert (await client.get(link.group(1))).status_code == 200

        assert (await client.post("/api/auth/sign-in/email", json=body)).status_code == 200
        me = await client.get("/api/me")
        assert me.json()["email"] == "ada@example.com"


asyncio.run(sign_up_verify_sign_in())
```

For tests of your own, `gotauth.testing` has a fake mailer, a fake clock and helpers:
see [Testing your auth](guides/testing.md).

## Next

- Social login: add `social_providers=[github(...)]` ([Social login](modules/social.md)).
- More sign-in methods: [two-factor](plugins/two-factor.md), [passkeys](plugins/passkeys.md),
  [magic links](plugins/magic-link.md).
- Keys for scripts and agents: [API keys](guides/api-keys.md).
- Sign-in for your MCP server: [MCP servers](guides/mcp.md).
- A frontend: the shadcn components in GotAuth's registry, used in
  [`examples/fastapi-nextjs`](https://github.com/gotauth/gotauth/tree/main/examples/fastapi-nextjs).
