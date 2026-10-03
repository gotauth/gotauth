# C1: Request pipeline, ASGI app, auth.api

| | |
|---|---|
| Lane / wave | Core / **Wave 1** |
| Size | M-L (2-3 agent-days) |
| Depends on | M0 (F2 contracts and kit, F3 crypto) |
| Can start | after M0 |
| Write scope | `src/gotauth/core/**`, `tests/core/`, `changes/C1.*.md` |
| Allowed new deps | none |

## Goal
`GotAuth` validates config, assembles core and plugins, and runs every request through one fail-closed pipeline (CONTRACTS 4, 5, 6, 10, 12.1, 13, 14). C1 ships no auth endpoints; C2-C4 plug in. Tests use stub endpoints and `fake_sessions()`.

## Build
- **Assembly** (13): build `ResolvedConfig`. ConfigError on: a secret < 32 chars; `base_url` not absolute, or http off localhost; `base_path` without a leading "/"; no sender off localhost while a plugin has `requires_email` or email + password runs with verification on (9); duplicate endpoint `id` or `(method, path)`, well-known included; colliding error codes; GET with `input_format` json or form. Merge schemas (SchemaConflictError); `bind_schema(schema, table_prefix=advanced.table_prefix)`.
- Lazy entry points (13.2): `crypto_kit` (F3), `session_service(config, secondary_storage=...)` (C3), `email_service(config, sender)` (D1). Installs `sessions_plugin()`, `email_password_plugin(config)` if enabled, `social_plugin()` if providers are given, then the user's plugins; core plugins stay out of `plugin_ids`. `advanced.session_service` / `email_service` override (tests inject fakes). Plugin `init` runs once, lazily, under a lock.
- **Pipeline** (`handle`), in the CONTRACTS section 5 order: route `(method, path)` with `{param}` (unknown or `server_only` -> NOT_FOUND) -> content-type check -> IP and IP + path rate limits -> parse and validate input -> principal resolution and principal checks, then `auth`, `scopes`, `fresh_session` -> origin check -> identifier and principal rate limits -> transaction { before hooks -> handler -> after hooks } -> events.
  - Body by `input_format` (default: GET query; POST, PATCH, DELETE json): json requires `Content-Type: application/json`, else UNSUPPORTED_MEDIA_TYPE (10.1); form requires `application/x-www-form-urlencoded`; query reads the query string. Validation errors -> INVALID_REQUEST, `details` with `loc`/`type`/`msg` only, never input values.
  - Principal (12.1), skipped for `auth="none"`: Bearer or `x-api-key` -> resolver with the longest matching prefix; unknown prefix or None -> UNAUTHENTICATED; else the session cookie via `ctx.sessions.get`. Then every `Plugin.principal_checks` entry (P6 rejects banned users there; C1 never reads plugin fields). Exceptions -> INTERNAL_ERROR, never a principal. `get_principal(headers, cookies)` runs the same steps.
  - Origin (10.1): POST/PATCH/DELETE authenticated by a cookie need a trusted `Origin` (`Referer` fallback); bearer and API-key requests are exempt. `scopes` -> INSUFFICIENT_SCOPE + `details.required`; `fresh_session`: session `created_at` within `fresh_age`.
- **Helpers:** `gotauth.core` re-exports `validate_redirect` and `resolve_client_ip`, which F2 implements in `contracts/protection.py` (CONTRACTS 4). C1 uses them and does not reimplement them.
- **`advanced.install_core_plugins`** (default True): False skips the automatic sessions, email + password and social plugins, so C1's tests and early tests in other work packages don't need C2-C4. The core plugin factories are imported only when installed.
- **`auth.api.call(id, ..., ctx=ctx)`** (CONTRACTS 12.5, 13): with `ctx`, the call joins the caller's transaction and principal, which is how plugins call each other.
- **Rate limits** (10.2): endpoint `rate_limit` > plugin rules > config `rules` > `DEFAULT_RATE_LIMITS`, most specific path wins. Keys `ip`, `ip_path`, `principal`, `identifier` (input field, lower-cased, or function; value hashed; None skips). Fixed windows on `memory` (clock-aware), `database` (C1-owned `rate_limit` model, ids `rlt`, merged only for this storage: `key` unique, `count`, `reset_at`) or `secondary` (`incr`), counted outside the request transaction. 429 RATE_LIMITED + `Retry-After`.
- **Transactions and events:** every endpoint runs in `adapter.transaction()`, GET included. `ctx.adapter` is wrapped so writes run the model's `DatabaseHooks` (plugin hooks in plugin order, then config). `ctx.emit` events reach `on_event` through `background()` after commit; dropped on rollback except `sign_in.failed`; `on_event` errors are only logged.
- **Errors:** AuthError -> `ErrorOut` (6); other exceptions -> INTERNAL_ERROR 500, logged without the body. JSON responses: `Cache-Control: no-store`. `error_format="oauth"` renders every error, pipeline errors included, as RFC 6749 `{error, error_description}` via the public `OAUTH_ERROR_MAP`: `invalid_request` 400 (INVALID_REQUEST, UNSUPPORTED_MEDIA_TYPE), `invalid_client` 401 + `WWW-Authenticate` (UNAUTHENTICATED, INVALID_CREDENTIALS), `invalid_grant` 400 (TOKEN_*), `invalid_scope` 400, `unauthorized_client` 400 (FORBIDDEN), `temporarily_unavailable` 429 + `Retry-After` (RATE_LIMITED), else `server_error` 500. Plugin codes `OAUTH_<NAME>` -> lower-case `<name>` with their registered status.
- **GotAuthInstance members** (13):
  - `complete_sign_in(ctx, user, *, method, remember_me=True)`: interceptors in plugin order (any may raise to block). A challenge sets `gotauth.challenge` (section 5: `cookie_name`, purpose `challenge`, `{user_id, type, methods, method, remember_me, exp}`, 10 minutes) -> ChallengeOut; else `ctx.sessions.create(..., remember_me=)` -> SignInOut (`token` only with `expose_token`). Emits `sign_in.succeeded`.
  - `finish_challenge(ctx, *, satisfied)`: missing or tampered cookie -> TOKEN_INVALID; expired -> TOKEN_EXPIRED; `satisfied` not in `methods` -> FORBIDDEN. Creates the session with the cookie's `remember_me`, clears the cookie, emits `sign_in.succeeded`.
  - `delete_user(ctx, user_id)` (`ctx` may be None, e.g. importers): user `before_delete` / `after_delete` hooks from config and plugins around the delete (FK cascades), run once even without a ctx; emits `user.deleted` when `ctx` is given.
  - `background(coro)`: tracked task, errors logged. `drain()`: awaits background tasks, then `email.drain()`.
- **Serving:** `asgi()` is pure ASGI, no Starlette: path relative to the mount, `url` from `base_url`, `client_ip` via `resolve_client_ip`, 1 MB body cap. `well_known()`: ASGI app for "/" serving `Plugin.well_known_endpoints` through the same pipeline, `{base_path}` in their paths replaced by the configured value; other paths 404. `api`: typed methods for every 13.1 id plus `call(id, ...)`; server calls skip origin checks and rate limits. `http`: shared httpx.AsyncClient, 10s timeout.
- Also owns (CONTRACTS 5, 10.1, 13):
  - `read_challenge(ctx) -> ChallengeState | None`
  - `create_user_record(ctx, data) -> User` (lower-cases the email, runs user create hooks, emits `user.created`)
  - the Content-Type rule applies only when the request has a body (empty bodies are exempt)

## Acceptance tests
- Against `memory_adapter()`, `fake_clock()`, `fake_sessions()` and stubs, via `auth.api` and `httpx.ASGITransport(auth.asgi())`.
- Each conflict (endpoint id, method + path, schema field, error code) and a `requires_email` plugin without a sender off localhost -> ConfigError.
- Hypothesis: validation errors never contain submitted values. `text/plain` or form body on a json endpoint -> 415; form bodies parse; a DELETE JSON body validates.
- Cookie POST without or with a wrong Origin -> ORIGIN_NOT_ALLOWED; exact and wildcard origins pass; bearer exempt. `//evil.com`, `/\evil.com`, `https://trusted.com.evil.com`, `https://evil.com@trusted.com`, `javascript:` rejected (Hypothesis over hosts).
- Hypothesis over request times: exactly `max` pass per window, correct `Retry-After`; an identifier rule counts one email across IPs; spoofed `x-forwarded-for` ignored without a trusted proxy.
- Fail closed: a raising resolver, principal check or hook -> 500, handler not run, no event. A principal check raising AuthError rejects with its code.
- No event after rollback except `sign_in.failed`; a failing `on_event` leaves the response unchanged; `drain()` waits for delivery.
- OAuth format: validation error, RATE_LIMITED and a plugin `OAUTH_INVALID_GRANT` render per the map.
- Challenge: cookie set, no session; `finish_challenge` keeps the cookie's `remember_me`; tampered, expired or unlisted `satisfied` rejected; a raising interceptor blocks sign-in.
- `delete_user` runs config and plugin hooks; a raising `before_delete` aborts. `well_known()` serves a stub endpoint with `{base_path}` substituted.
- With `install_core_plugins=False`, `GotAuth(...)` constructs and serves stub endpoints even when the C2-C4 modules are empty skeletons.
- A plugin endpoint calling `auth.api.call(<stub endpoint id>, ctx=ctx)` on a `stub_plugin` runs in one transaction: a failure in the callee rolls back the caller's writes.

## Out of scope
- The 13.1 endpoints (C2, C3, C4); FastAPI router and OpenAPI (A1); the content of O1's metadata documents.

## Notes
- Plugins (P2) read the pending challenge only through `ctx.auth.read_challenge(ctx)` and end it only through `finish_challenge`; they never unsign the cookie themselves.
