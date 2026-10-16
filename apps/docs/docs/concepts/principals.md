# Principals and scopes

Every authenticated request resolves to one **principal**: who the request acts for,
how it proved it, and what it may do. Your routes depend on the principal, not on the
kind of credential.

| `principal.via` | Credential | Typical caller |
|---|---|---|
| `session` | The session cookie, or `Authorization: Bearer gas_...` | A browser, a mobile app |
| `api_key` | `x-api-key: gak_...` or `Authorization: Bearer gak_...` | A script, CI, an agent |
| `oauth_token` | `Authorization: Bearer eyJ...` (a GotAuth access token) | An MCP client, a third-party app |

The other fields:

- `user_id`: the human the request acts for. Never an agent or client id.
- `agent_id`: set when an [agent](../guides/agents.md) acts, for the user in `user_id`.
- `organization_id`: the session's active organization, or the organization that owns
  a key.
- `client_id`: the OAuth client, for `oauth_token`.
- `credential_id`: the session, key or token row, for audit logs.
- `scopes`: what the credential may do. `None` for a session: a signed-in user has the
  full rights of their account.

## Scopes

Scopes are flat strings, written `resource:action`: `projects:read`,
`projects:write`. No scope implies another, so `projects:write` does not include
`projects:read`. API keys get the scopes chosen when they are created (from the
plugin's `allowed_scopes`); OAuth tokens get the scopes the user consented to.

## Protecting routes in FastAPI

<!-- sample: skip: needs the app from the quickstart -->
```python
from typing import Annotated

from fastapi import Depends

from gotauth import Principal, User

CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]               # sessions
CurrentPrincipal = Annotated[Principal, Depends(auth.fastapi.current_principal)]  # any credential
ApiKeyPrincipal = Annotated[Principal, Depends(auth.fastapi.api_key_principal)]   # keys only
CanRead = Annotated[Principal, Depends(auth.fastapi.require("projects:read"))]    # scope check


@app.get("/api/v1/projects")
async def projects(principal: CanRead) -> list[str]: ...
```

- `current_user` accepts sessions only, and gives the `User`.
- `current_principal` accepts any credential and runs the plugins' principal checks
  (for example, the admin plugin refuses banned users).
- `require("projects:read")` answers 403 `INSUFFICIENT_SCOPE` with
  `details.required` when the credential lacks the scope. Sessions have every scope, so
  pair it with `api_key_principal` when a route is for keys only.
- With the [organization plugin](../plugins/organizations.md),
  `require(permission={"project": ["read"]})` checks the caller's role in the active
  organization, and narrows keys and tokens by their scopes.

Other frameworks: [Starlette and Litestar](../integrations/starlette-litestar.md); any
ASGI app can call `await auth.get_principal(headers, cookies)`.
