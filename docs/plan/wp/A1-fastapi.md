# A1: FastAPI integration

| | |
|---|---|
| Lane / wave | Integration / **Wave 2** (critical path to M2) |
| Size | M |
| Depends on | M0 (testing kit); C1-C3 for end-to-end tests |
| Can start | after M0: routes and OpenAPI from `CORE_ENDPOINTS` with `gotauth.testing`; round trips once C1 lands (`make_auth` needs it) |
| Write scope | `src/gotauth/integrations/fastapi/**`, `tests/integrations/fastapi/**`, `changes/A1.*.md` |
| Allowed new deps | runtime: `fastapi` (existing extra, lazy import); dev: none |

## Goal
Real FastAPI routes with correct OpenAPI, `Annotated` dependencies and a scope/permission guard, returned by `auth.fastapi` (13). `import gotauth` never imports FastAPI.

## Build
- `FastAPIIntegration`, built lazily; FastAPI missing -> `ConfigError` naming `gotauth[fastapi]`.
- `router() -> APIRouter`: one route per endpoint with `server_only=False` (13.1 + plugins): `operation_id=id`, `summary`, `tags`, `response_model=output` (13.1 output column, e.g. `SessionWithUserOut | None` for `get_session`); `input` per `input_format`: JSON body (POST, PATCH, DELETE by default; `delete_user` has one), form body (`"form"`, e.g. `social_callback_post`, O1 token endpoints) or query params (GET); `{param}` as path params. Errors documented with `ErrorOut` (6), or an RFC 6749 error schema for `error_format="oauth"`.
  - A custom `APIRoute` subclass uses the models for OpenAPI only and passes the raw request to `auth.handle()`: content-type checks (415), validation (400 `INVALID_REQUEST`, never 422) and form parsing all stay in C1.
  - Include with `prefix == base_path`; checked on first request and by `check_app(app)`, mismatch -> `ConfigError`.
- Request -> `AuthRequest` (4): `client_ip` from `gotauth.core.resolve_client_ip(peer, headers, config)`, never a local copy.
- `AuthResponse` -> Response: JSON with `Cache-Control: no-store`, HTML, 302 redirect, headers, every `SetCookie` attribute.
- Dependencies, as callables on `auth.fastapi`:
  - `current_user`: session user (cookie or bearer `gas_`), else 401 `UNAUTHENTICATED`. Via `auth.api.get_session(..., as_response=True)` (`SessionWithUserOut`); copies refreshed cookies to the response.
  - `optional_user`; `current_session` (`SessionWithUser`).
  - `current_principal`: `auth.get_principal(...)` (12.1, principal checks included, so banned users are rejected by P6's check), else 401.
  - `api_key_principal`: `via == "api_key"`, else 401.
- Aliases are defined in app code, as in `docs/build-plan.md`: `CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]`, likewise `OptionalUser`, `CurrentSession`, `CurrentPrincipal`, `ApiKeyPrincipal`. README, docstrings and examples use this form; pyright strict rejects `user: auth.fastapi.CurrentUser` (a variable in a type expression).
- `require(*scopes, permission=None)` -> dependency returning the `Principal`: missing scopes -> 403 `INSUFFICIENT_SCOPE` + `details.required`. `permission` is `{resource: [action]}`, the same vocabulary as scopes (`"project:delete"`, 12.1), checked with `auth.api.call("has_permission", body={"permissions": ...}, headers=...)` (12.3); `success=false` -> 403 `FORBIDDEN`. Without P5, `require(permission=...)` raises `ConfigError` at startup.
- `add_exception_handlers(app)`: `AuthError` -> section 6 JSON, `Retry-After` on 429, `WWW-Authenticate: Bearer` on 401.
- Well-known documents: documented as `app.mount("/", auth.well_known())` (13), added after the app's own routes so they keep priority, exactly as in `docs/build-plan.md`.

## Acceptance tests
- OpenAPI snapshot of every 13.1 endpoint (method, path, operationId, body/form/query/path params, response schema, tags); no 422 anywhere.
- Invalid body -> 400 `INVALID_REQUEST`, section 6 shape, no input values echoed; a `text/plain` body -> 415.
- httpx `ASGITransport`: sign up, sign in, cookie attributes, sign out; HTML and redirects pass through. Wrong include prefix -> `ConfigError`.
- Each dependency with cookie, bearer `gas_`, `gak_` key and OAuth JWT principals (`gotauth.testing.stub_resolver` for `gak_` / `eyJ` until P1/O1 merge, `TODO(A1)`); missing or revoked -> 401; `ApiKeyPrincipal` with a session -> 401; a test principal check raising -> rejected.
- `require("projects:read")`: session passes; key without the scope -> 403 with `details.required`.
- Spoofed `X-Forwarded-For` from an untrusted peer ignored (Hypothesis over headers and proxy sets).
- Cookie POST without `Origin` -> 403 `ORIGIN_NOT_ALLOWED`. Exception in a dependency -> 500 `INTERNAL_ERROR`.
- `app.mount("/", auth.well_known())` serves a stub plugin's well-known endpoint without shadowing app routes.
- An app using the `CurrentUser` alias form passes pyright strict.
- `import gotauth` does not import `fastapi` (subprocess).

## Out of scope
Pipeline, rate limits and client-IP logic (C1); Starlette/Litestar (A2); `has_permission` (P5); resolvers (P1, O1).

## Notes
- Query-parameter models need FastAPI >= 0.115. Target the current release as of 2026-10, check the docs (custom `APIRoute`, router lifespan, mounts) and record the version.
