# API keys

API keys let scripts, CI jobs and agents call your API without a browser session. Each
key is shown once, stored only as a hash, limited to the scopes you allow, and revocable
at any time.

## Set up

<!-- sample: skip: a configuration fragment; the runnable version is below -->
```python
from gotauth.plugins.api_key import api_key

auth = GotAuth(..., plugins=[api_key(allowed_scopes=["projects:read", "projects:write"])])
```

`allowed_scopes` lists every scope a key may carry; with none, keys carry no scopes.
Then create the `auth_api_key` table (`gotauth migrate`, or `gotauth generate` with
Alembic).

## Protect a route for keys

<!-- sample: skip: needs a FastAPI app; the HTTP flow is below -->
```python
ApiKeyPrincipal = Annotated[Principal, Depends(auth.fastapi.api_key_principal)]
CanRead = Annotated[Principal, Depends(auth.fastapi.require("projects:read"))]


@app.get("/api/v1/projects")
async def projects(key: ApiKeyPrincipal, _: CanRead) -> list[str]:
    return projects_of(key.user_id)
```

`api_key_principal` accepts keys only. `require("projects:read")` checks the scope; a
key without it gets 403 `INSUFFICIENT_SCOPE` naming the missing scope.

## The whole flow

A signed-in user creates a key (it is in this answer only), a script uses it, and
revoking it ends it on the next request:

<!-- sample: run -->
```python
import asyncio

from gotauth import AuthError
from gotauth.plugins.api_key import api_key
from gotauth.testing import make_auth, make_client

auth = make_auth(
    plugins=[api_key(allowed_scopes=["projects:read"])],
    email_password={"require_email_verification": False},
)


async def flow() -> None:
    async with make_client(auth) as browser:
        await browser.post(
            "/sign-up/email",
            json={"email": "ada@example.com", "password": "correct horse battery"},
        )
        created = await browser.post(
            "/api-keys", json={"name": "ci", "scopes": ["projects:read"], "expires_in": "90d"}
        )
        key = created.json()["key"]  # gak_...: show it once, never store it
        key_id = created.json()["api_key"]["id"]

    principal = await auth.get_principal({"x-api-key": key}, {})
    assert principal is not None and principal.via == "api_key"
    assert principal.scopes == frozenset({"projects:read"})

    async with make_client(auth) as browser:
        await browser.post(
            "/sign-in/email",
            json={"email": "ada@example.com", "password": "correct horse battery"},
        )
        await browser.delete(f"/api-keys/{key_id}")
    try:
        await auth.get_principal({"x-api-key": key}, {})
    except AuthError as error:
        assert (error.code, error.status) == ("API_KEY_INVALID", 401)
    else:
        raise AssertionError("a revoked key still works")


asyncio.run(flow())
```

Clients send the key as `x-api-key: gak_...` or `Authorization: Bearer gak_...`. A
revoked, disabled or expired key gets a 401 with `API_KEY_INVALID`, `API_KEY_DISABLED`
or `API_KEY_EXPIRED`.

## Good practice

- Give each script or machine its own key, with the fewest scopes and an expiry
  (`expires_in`, capped by `max_expires_in`).
- Rate-limit keys with `api_key(rate_limit=(1000, 3600))` or per key; with several
  processes, configure `secondary_storage` so the limit is shared.
- Keys for an organization act for the organization, not a user: create them with
  `organization_id` (needs the [organization plugin](../plugins/organizations.md)).
- Keys for an AI agent belong to the agent, so revoking the agent revokes them: see
  [Agents](agents.md).

The [API keys plugin page](../plugins/api-keys.md) has every option and error code.
