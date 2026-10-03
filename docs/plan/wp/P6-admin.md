# P6: Admin

| | |
|---|---|
| Lane / wave | Plugins / **Wave 3** (cut-list item 3) |
| Size | S-M |
| Depends on | C3 (`SessionService.create` with `expires_in`, `extra`); C1 (interceptors, principal checks, `delete_user`) |
| Can start | after M2, or earlier against `gotauth.testing` |
| Write scope | `src/gotauth/plugins/admin/**`, `tests/plugins/admin/**`, `changes/P6.*.md` |
| Allowed new deps | none |

## Goal
An `admin()` plugin (id `"admin"`, `from gotauth.plugins.admin import admin`) for app administrators: find, create, ban and remove users, set roles and passwords, manage their sessions and impersonate them. Every endpoint is admin-only.

## Build
- Schema: user fields `role` (string, default "user"), `banned` (boolean, default False), `ban_reason` (optional), `ban_expires_at` (datetime, optional), all `input=False`. Session field `impersonated_by` (-> user, set_null, `input=False`).
- Config: `admin_roles` ("admin",), `admin_user_ids` (()), `impersonation_expires_in` "1h", `allow_impersonating_admins` False.
- Admin check, first thing in every handler except `stop_impersonating`: `principal.via == "session"`, not an impersonation session, and `role` in `admin_roles` or id in `admin_user_ids`; else `FORBIDDEN`.
- Endpoints (ids verb first, all `session`; `{user_id}` is the target):
  - `list_users` GET `/admin/users`: `search` (email or name), `sort_by`, `sort_direction`, `limit` (<= 100), `offset`; returns `{users, total}`.
  - `get_user` GET `/admin/users/{user_id}`; `create_user` POST `/admin/users` (`{email, password?, name?, role?, email_verified?}`, emits `user.created`); `remove_user` DELETE `/admin/users/{user_id}` (fresh): calls `ctx.auth.delete_user(ctx, user_id)` (13), the only way to delete a user, so config and plugin database hooks run; emits `user.deleted`.
  - `set_user_role` POST `/admin/users/{user_id}/role` (emits `user.role_changed`); `set_user_password` POST `/admin/users/{user_id}/password` (fresh; creates or updates the `credential` account, revokes the user's sessions, emits `password.changed`).
  - `ban_user` POST `/admin/users/{user_id}/ban` (`{reason?, expires_in?}`; `revoke_all` sessions; emits `user.banned`); `unban_user` POST `/admin/users/{user_id}/unban` (emits `user.unbanned`). Admins cannot ban themselves.
  - `list_user_sessions` GET `/admin/users/{user_id}/sessions` (shows `impersonated_by`); `revoke_user_sessions` POST `/admin/users/{user_id}/sessions/revoke`.
  - `impersonate_user` POST `/admin/users/{user_id}/impersonate` (fresh): `ctx.sessions.create(ctx, target_id, expires_in=impersonation_expires_in, extra={"impersonated_by": admin_id})` (section 7); the admin's session token moves to the signed HttpOnly cookie `gotauth.admin_session`; emits `admin.impersonation_started` `{admin_id, target_id}`. `stop_impersonating` POST `/admin/stop-impersonating` (session must have `impersonated_by`): revokes it, restores the admin cookie if that session is still valid, emits `admin.impersonation_stopped`.
- Bans (`ADMIN_USER_BANNED`, 403, registered here). A past `ban_expires_at` counts as unbanned and is cleared on the next check.
  - Sign-in: a `SignInInterceptor` raises `ADMIN_USER_BANNED` for a banned user. Interceptors run after the credential check, so a wrong password still gets `INVALID_CREDENTIALS`.
  - Requests: a `PrincipalCheck` (`Plugin.principal_checks`, section 5) rejects sessions, API keys and OAuth tokens whose `user_id` is banned. P1 and O1 have no ban checks of their own. The banned flag may be cached per user for up to 5 seconds.
  - Ban also revokes sessions, so the user is out at once.
- New users are created only through `ctx.auth.create_user_record(ctx, data)` (CONTRACTS 13), so user database hooks run and `user.created` is emitted.

## Acceptance tests
- Parametrized over the plugin's endpoint list: non-admin session -> `FORBIDDEN`, anonymous -> `UNAUTHENTICATED`, API key of an admin -> `FORBIDDEN`. New endpoints are covered automatically.
- Ban: the user's next request with the old cookie -> 401 (cookie cache off); sign-in with the right password -> `ADMIN_USER_BANNED`; with `expires_in="1h"`, sign-in works after `fake_clock.advance("61m")`.
- A banned user's API key (`stub_resolver("gak_", ...)` until P1 merges) and OAuth token principal -> `ADMIN_USER_BANNED`; unban -> accepted again.
- `remove_user` runs a test plugin's user `before_delete` hook and cascades the user's sessions.
- `update_user` cannot set `role`, `banned` or `ban_*`; `create_user` input cannot set `banned`.
- Impersonation: the session has `impersonated_by`, shows in `list_user_sessions`, expires after 1 hour, cannot call admin endpoints; `stop_impersonating` restores the admin; non-fresh admin -> `FRESH_SESSION_REQUIRED`; impersonating an admin is refused by default.
- Every ban, unban, role change and impersonation start/stop emits its event (14).
- Hypothesis: paging through `list_users` with any `limit` returns every user exactly once.

## Out of scope
Hosted dashboard (X2), org-level administration (P5), audit log storage (X1), admin UI (D2).

## Notes
- With `cookie_cache` on, the `PrincipalCheck` still runs on every request, so a banned user's cached session is rejected; document the extra user lookup.
