# gotauth.integrations.asgi

GotAuth for Starlette and Litestar apps, without FastAPI. Work package A2. Built
against Starlette 1.7.0 and Litestar 2.24.0 (checked 2026-10-08). `import gotauth`
imports neither framework; import the module you use.

Client IP, origin checks, content types and rate limits all happen inside
`auth.asgi()`; these adapters only mount it and read the principal.

## Starlette (`pip install "gotauth[starlette]"`)

```python
from starlette.applications import Starlette
from starlette.authentication import requires
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from gotauth.integrations.asgi.starlette import gotauth_middleware, requires_scopes


@requires("authenticated")
async def me(request):
    return JSONResponse({"id": request.user.identity})


@requires_scopes("projects:read")
async def projects(request):
    return JSONResponse({"principal": request.user.principal.via})


app = Starlette(
    routes=[
        Route("/me", me),
        Route("/projects", projects),
        Mount(auth.config.base_path, app=auth.asgi()),
        Mount("/", app=auth.well_known()),  # last, so your routes keep priority
    ],
    middleware=[gotauth_middleware(auth)],
)
```

- `GotAuthBackend` resolves the principal with `auth.get_principal` for HTTP and
  WebSocket connections; `request.user` is a `GotAuthUser` (`identity`, `user_id`,
  `principal`) or Starlette's anonymous user.
- Credential scopes: always `authenticated`; sessions add `session`; API keys and OAuth
  tokens add their own scopes.
- Sessions have full rights, which Starlette's `@requires("projects:read")` cannot
  express; use `requires_scopes(...)`, which lets sessions through and answers 401 or
  403 `INSUFFICIENT_SCOPE` (with `details.required`) in GotAuth's error shape.
- A bad credential answers with the GotAuth error (for example 401
  `API_KEY_INVALID`); an unexpected failure is 500 `INTERNAL_ERROR`, never a user.

## Litestar (`pip install "gotauth[litestar]"`)

```python
from litestar import Litestar, get
from litestar.di import NamedDependency

from gotauth import Principal, User
from gotauth.integrations.asgi.litestar import GotAuthPlugin, requires_scopes, requires_session


@get("/me")
async def me(current_user: NamedDependency[User]) -> dict[str, str]:
    return {"id": current_user.id}


@get("/projects", guards=[requires_scopes("projects:read")])
async def projects(principal: NamedDependency[Principal | None]) -> dict[str, str]:
    return {"via": principal.via if principal else "anonymous"}


app = Litestar(route_handlers=[me, projects], plugins=[GotAuthPlugin(auth)])
```

- `GotAuthPlugin` mounts `auth.asgi()` at `base_path` and `auth.well_known()` at
  `/.well-known` (not `/`: a Litestar mount at `/` takes every request, app routes
  included; every GotAuth well-known document lives below `/.well-known`).
- Dependencies: `principal` (`Principal | None`) and `current_user` (`User`, 401
  without a session). Guards: `requires_session` and `requires_scopes(*scopes)`.
- `AuthError` is rendered in GotAuth's error shape.
