# A2: Starlette + Litestar integration

| | |
|---|---|
| Lane / wave | Integration / **Wave 2** (parallel) |
| Size | S-M |
| Depends on | C1 (`auth.asgi()`, `auth.well_known()`, `auth.get_principal()`) |
| Can start | after C1 merges; the auth backend earlier against a stub `get_principal` |
| Write scope | `src/gotauth/integrations/asgi/**`, `tests/integrations/asgi/**`, `changes/A2.*.md` |
| Allowed new deps | runtime: `starlette` and `litestar` (existing extras, CONTRACTS section 0), both imported lazily; dev: none |

## Goal
Let Starlette and Litestar apps use GotAuth without FastAPI: mount the ASGI app, read the principal on every request, and guard routes by session or scopes. Starlette first; Litestar is item 2 on the cut list.

## Build
- `gotauth.integrations.asgi.starlette` (install: `pip install "gotauth[starlette]"`):
  - Documented mounting: `Mount(base_path, app=auth.asgi())`, plus `Mount("/", app=auth.well_known())` as the last route (13; it serves every plugin's `well_known_endpoints`, e.g. O1's RFC 8414 metadata).
  - `GotAuthBackend(auth)`, a Starlette `AuthenticationBackend`: calls `auth.get_principal(headers, cookies)` (12.1; C1 runs the principal checks there) and returns `(AuthCredentials(scopes), GotAuthUser)` or `None`. Works for HTTP and WebSocket connections.
  - `GotAuthUser(BaseUser)`: `is_authenticated`, `display_name`, `identity` (user id, else agent id, else credential id), `principal`, `user_id`.
  - Credential scopes: always `"authenticated"`; sessions add `"session"`; API keys and OAuth tokens add their own scopes. Sessions have full rights (`scopes=None`), so Starlette's `@requires("projects:read")` fails for them by design: add `requires_scopes(*scopes)`, which uses `Principal.has_scopes` and returns 403 `INSUFFICIENT_SCOPE` with `details.required`.
  - `on_error` returning 401 in the section 6 shape. An exception in the backend fails closed: 500 `INTERNAL_ERROR`, never a user.
- `gotauth.integrations.asgi.litestar` (install: `pip install "gotauth[litestar]"`):
  - `GotAuthPlugin(auth)` implementing `InitPluginProtocol.on_app_init`: mounts `auth.asgi()` at `base_path` and `auth.well_known()` at "/" as ASGI mounts; app routes must keep priority over the "/" mount.
  - Dependency providers: `principal` (`Principal | None`) and `current_user` (`User`, 401 `UNAUTHENTICATED` without a session), via `auth.get_principal` and `auth.api.get_session` (`SessionWithUserOut`).
  - Guards: `requires_session`, `requires_scopes(*scopes)` (403 `INSUFFICIENT_SCOPE`).
  - Exception handler mapping `AuthError` to the section 6 shape.
- Client IP, origin checks, content-type checks and rate limits all happen inside `auth.asgi()` (C1, `resolve_client_ip`); A2 never re-implements them.
- Module README with a copy-paste example per framework and the targeted versions.

## Acceptance tests
- Starlette (httpx `ASGITransport` or `TestClient`): sign up and sign in through the mount; `request.user.is_authenticated` is correct for cookie, bearer `gas_`, `gak_` key (`gotauth.testing.stub_resolver` until P1 merges) and no credential.
- `@requires("authenticated")` works; `requires_scopes("projects:read")` passes a session, rejects a key without the scope (403), accepts a key with it.
- A WebSocket connection resolves the same principal from the cookie.
- The "/" well-known mount serves a stub plugin's endpoint and app routes still answer (both frameworks).
- Litestar `AsyncTestClient`: the plugin mounts the auth app; `current_user` gives 401 without a session; guards return 401 and 403 correctly.
- A backend exception yields 500 and no user.
- `import gotauth` imports neither Starlette nor Litestar.

## Out of scope
FastAPI router, OpenAPI and `Annotated` dependencies (A1); `auth.asgi()`, `auth.well_known()`, origin checks and rate limits (C1); Flask and Django (A3); the `litestar-htmx` example (G4).

## Notes
- Target the current Starlette and Litestar releases as of 2026-10. Check current docs for `AuthenticationBackend`, `InitPluginProtocol`, ASGI mounts (route priority against a "/" mount) and guard signatures, and record the versions in the README.
- If behind schedule, ship Starlette only (cut list item 2) and tell G4 to drop `examples/litestar-htmx`.
