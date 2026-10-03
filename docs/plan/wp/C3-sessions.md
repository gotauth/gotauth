# C3: Sessions, cookies, bearer, cookie cache

| | |
|---|---|
| Lane / wave | Core / **Wave 1** |
| Size | M (2 agent-days) |
| Depends on | M0 |
| Can start | after M0 |
| Write scope | `src/gotauth/sessions/**`, `tests/sessions/`, `changes/C3.*.md` |
| Allowed new deps | none (`redis` is the existing extra, imported lazily) |

## Goal
The SessionService of CONTRACTS section 7, its four endpoints and the `gas_` principal resolver. Session tokens are hashed at rest, rotated on every sign-in and read from a cookie or a bearer header.

## Build
- Entry points (13.2): `session_service(config: ResolvedConfig, *, secondary_storage: SecondaryStorage | None = None) -> SessionService` and `sessions_plugin() -> Plugin` (id `sessions`: the endpoints below + the resolver; config is read from `ctx.auth.config` at request time). C1 installs it first.
- `create(ctx, user_id, *, remember_me=True, expires_in=None, extra=None)`: always a new token `crypto.random_token("gas_")` (fixation protection: never reuse a token from the request); store only `hash_token`; store `remember_me` on the row; `expires_at` = now + `expires_in` if given, else `sessions.expires_in` (7d), or `sessions.short_expires_in` (1d) when `remember_me=False`; `ip_address` = `ctx.request.client_ip`, `user_agent` truncated to 512; `extra` merged into the row (plugin fields); set the cookie.
- `get(ctx, token)`: prefix check, lookup by hash, expired -> delete and None, load the user. Sliding refresh once now - `updated_at` >= `update_age`: compare-and-set on `updated_at`; new `expires_at` = now + `expires_in` or `short_expires_in` by the row's `remember_me`, never earlier than the current value; cookie re-set. This write on `GET /session` is allowed bookkeeping (7, AGENT-RULES).
- `list_for_user`, `revoke` (emit `session.revoked`), `revoke_all(except_session_id=)`, `clear_cookies` (session and cache cookies).
- Cookies via `contracts.sessions.cookie_name` / `secure_cookies` with `advanced.cookie_prefix`: `gotauth.session_token`, `__Secure-gotauth.session_token` when `base_url` is https (every GotAuth cookie, the cache included); HttpOnly; Secure except on `http://localhost` and `127.0.0.1`; SameSite=Lax; Path=/; Max-Age = seconds until `expires_at`, none when `remember_me=False` (browser-session cookie).
- Cookie cache (`sessions.cookie_cache.enabled`, default off): `gotauth.session_data` = `crypto.sign(b64url(JSON {session, user, exp, th}), purpose="session_data")`; `th` is an HMAC of the session token so the cache only works with its own token; valid until `exp` (`max_age`, default 5m) and skips the database; not set when over 3.5 KB. The README states that revocation can take up to `max_age`.
- Bearer `Authorization: Bearer gas_...` when `allow_bearer` (default True). Resolver (`prefixes=("gas_",)`) -> `Principal(via="session", credential_id=session.id, user_id=..., organization_id=session.active_organization_id when the field exists (P5), scopes=None)`. C1 reads the cookie and calls `get`.
- Endpoints (13.1):
  - `get_session` GET `/session` (optional): `SessionWithUserOut`, or `null`.
  - `list_sessions` GET `/sessions` (session): SessionListOut `{sessions, current_session_id}`.
  - `revoke_session` POST `/sessions/revoke` (session) `{session_id}`: own sessions only, else NOT_FOUND; clears cookies when it is the current one.
  - `revoke_other_sessions` POST `/sessions/revoke-others` (session): StatusOut.
- SecondaryStorage (13.2 names): `memory_secondary_storage(*, clock=None)` and `redis_secondary_storage(url=None, *, client=None, key_prefix="gotauth:")`; atomic `incr` that sets the TTL only on the first increment (Lua script or MULTI). When configured, sessions are cached by token hash with a TTL to `expires_at` and deleted on revoke.
- `expose_token`: C1's `complete_sign_in` adds `token` to SignInOut; nothing else exposes raw tokens.

## Acceptance tests
- After create, get, refresh and revoke, no row in any model contains a raw `gas_` token (memory adapter dump).
- Hypothesis with `fake_clock`: `get` returns None iff now >= `expires_at`; refresh only after `update_age`; `expires_at` never moves backwards; `remember_me=False` sessions never extend more than `short_expires_in` past their last refresh; an explicit `expires_in` shorter than `update_age` never slides.
- 20 concurrent `get`s due for refresh -> exactly one update.
- Each sign-in yields a new token; a token presented at sign-in is never reused.
- Cookie name and attributes for https, `http://localhost`, `http://127.0.0.1`; no Max-Age when `remember_me=False`.
- Cache: tampered or foreign-token cookie ignored; revocation visible after `max_age`.
- Bearer: revoked session -> UNAUTHENTICATED on the next request; `revoke_other_sessions` keeps the current one; another user's `session_id` -> NOT_FOUND.
- Resolver copies `active_organization_id` when a test plugin adds the field.
- Redis storage against the compose service (`redis` marker): TTL set once, `incr` atomic under `gather`; memory storage TTL with `fake_clock`.
- Endpoint objects match `CORE_ENDPOINTS` for the C3 rows.

## Out of scope
- Sign-in flows (C2, C4, plugins) and `complete_sign_in` (C1); pipeline and cookie parsing (C1); `active_organization_id` itself (P5); impersonation (P6).

## Notes
- `session_service` takes `secondary_storage` as an optional keyword because 13.2 shows only `config`; C1 passes the `GotAuth(secondary_storage=...)` value.
