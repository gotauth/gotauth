# gotauth.integrations.fastapi

FastAPI routes, dependencies and exception handlers: `auth.fastapi`. Work package A1.
Needs the `fastapi` extra; built against FastAPI 0.142.2 (Starlette 1.7.0), checked
2026-10-07. `import gotauth` never imports FastAPI.

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from gotauth import GotAuth, Principal, User

auth = GotAuth(...)
app = FastAPI()
app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
auth.fastapi.add_exception_handlers(app)

CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]
OptionalUser = Annotated[User | None, Depends(auth.fastapi.optional_user)]
CurrentPrincipal = Annotated[Principal, Depends(auth.fastapi.current_principal)]
ApiKeyPrincipal = Annotated[Principal, Depends(auth.fastapi.api_key_principal)]
ProjectReader = Annotated[Principal, Depends(auth.fastapi.require("projects:read"))]


@app.get("/projects")
async def projects(user: CurrentUser) -> list[str]: ...


# Last, so your own routes keep priority.
app.mount("/", auth.well_known())
```

Define the aliases at module level as above: type checkers reject
`user: auth.fastapi.CurrentUser` (a variable in a type expression).

## Router

One route per HTTP endpoint (core and plugins), with the endpoint id as `operationId`,
its input as JSON body, form body or query parameters, and its output as the response
model. FastAPI only documents the request: the raw request goes to `auth.handle()`, so
content types (415), validation (400 `INVALID_REQUEST`, never 422) and form parsing stay
in GotAuth's pipeline. Errors are documented as `ErrorOut` (or the RFC 6749 shape for
OAuth endpoints) under `4XX`.

Include the router with `prefix=auth.config.base_path`. A wrong prefix raises
`ConfigError` on the first request; `auth.fastapi.check_app(app)` checks it at startup.
The router's lifespan waits for background deliveries (`auth.drain()`) on shutdown.

## Dependencies

| Dependency | Gives | 401 when |
|---|---|---|
| `current_user` | `User` (session cookie or `Bearer gas_...`) | no session |
| `optional_user` | `User \| None` | never |
| `current_session` | `SessionWithUser` | no session |
| `current_principal` | `Principal` from a session, API key or OAuth token; principal checks run (bans) | no credential |
| `api_key_principal` | `Principal` from an API key only | anything else |
| `require(*scopes, permission=None)` | `Principal` | as `current_principal`; 403 `INSUFFICIENT_SCOPE` with `details.required`, or 403 `FORBIDDEN` from the organization plugin's `has_permission` |

Sessions have every scope. `require(permission=...)` without the organization plugin
raises `ConfigError` when the dependency is created.

`add_exception_handlers(app)` renders `AuthError` from dependencies and your own routes
as GotAuth's JSON error, with `Retry-After` on 429 and `WWW-Authenticate: Bearer` on 401.
