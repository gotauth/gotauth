# A3: Flask + Django integrations

| | |
|---|---|
| Lane / wave | Integration / **Wave 4** (only on request) |
| Size | M each |
| Depends on | C1 |
| Can start | only after M3 and a passed post-launch test, one framework at a time, when users ask for it |
| Write scope | `src/gotauth/integrations/flask/**`, `src/gotauth/integrations/django/**`, `tests/integrations/flask/**`, `tests/integrations/django/**`, `changes/A3.*.md`, `docs/requests/A3-*.md` |
| Allowed new deps | runtime, lazy, behind the `flask` / `django` extras (CONTRACTS section 0, Phase 4): `flask`, `django`, `a2wsgi` or `asgiref`; dev: `pytest-django` if Django is built. Only F1-owned `pyproject.toml` declares them: file `docs/requests/A3-extras.md` with the diff first |

## Goal
Let Flask and Django apps use GotAuth users and principals, mainly when they share users with a FastAPI service.

## Build
- Flask (`gotauth.integrations.flask`):
  - `GotAuthFlask(auth, app=None)` with `init_app(app)`: serves `auth.asgi()` under `base_path` and `auth.well_known()` for `/.well-known/` paths through an ASGI -> WSGI bridge (a2wsgi or asgiref) with a dispatcher.
  - `current_user` and `current_principal` proxies, resolved once per request via `auth.get_principal` (principal checks included) and cached on `g`.
  - `@login_required` and `@requires_scopes(*scopes)` returning 401/403 in the section 6 shape.
  - Sync views reach async GotAuth through the bridge's event loop; document the per-request cost.
- Django (`gotauth.integrations.django`):
  - `gotauth_urls(auth)` for `path("api/auth/", include(...))`, routing to `auth.handle()` through an async view; a matching route set for the `auth.well_known()` paths at the root.
  - Middleware setting a lazy `request.principal` and `request.gotauth_user`; it does not replace `django.contrib.auth`.
  - Decorators `gotauth_login_required` and `requires_scopes(*scopes)`.
- Client IP from `gotauth.core.resolve_client_ip(peer, headers, config)` (4), never re-implemented.

## Acceptance tests
- Flask test client: sign up and sign in through the bridge; `current_user` set for cookie, bearer `gas_` and `gak_` key (`gotauth.testing.stub_resolver` if P1 is absent); decorators return 401/403 in the section 6 shape.
- Django test client (sync and async views): same checks, plus CSRF middleware does not block GotAuth's own endpoints, which rely on the origin and content-type checks (10.1).
- A stub plugin's well-known endpoint is reachable at the root in both frameworks.
- Exceptions in the middleware fail closed (500, no principal).
- `import gotauth` imports neither Flask nor Django.

## Out of scope
FastAPI (A1), Starlette/Litestar (A2), Django ORM adapter (S2).

## Notes
- django-allauth already serves Django well (headless mode, MFA, passkeys, OIDC provider). Build Django only on clear public demand, and position it for apps sharing GotAuth users with a FastAPI service, not as an allauth replacement.
- The `django` extra is shared with S2b; coordinate the request so it is added once.
- Check current Flask, Django, a2wsgi and asgiref docs; record versions.
