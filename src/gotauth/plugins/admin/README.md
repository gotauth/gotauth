# gotauth.plugins.admin

Admin (work package P6): app administrators find, create, ban and remove users, set
their roles and passwords, manage their sessions and impersonate them.

```python
from gotauth.plugins.admin import admin

auth = GotAuth(..., plugins=[admin(admin_user_ids=("usr_01J...",))])
```

The first admin is usually named by id in `admin_user_ids`. That admin can then give
others the `admin` role with `set_user_role`.

## Options

- **`admin_roles`:** roles that make a user an admin, `("admin",)` by default.
- **`admin_user_ids`:** users who are admins whatever their role.
- **`impersonation_expires_in`:** `"1h"` by default. An impersonation session never
  slides past it.
- **`allow_impersonating_admins`:** `False` by default.
- **`impersonation_blocked`:** endpoint ids an impersonation session may not call.
  The default, `IMPERSONATION_BLOCKED`, covers everything that creates a credential
  that would outlive the impersonation (API keys, agents, OAuth clients and grants)
  and the account's security settings (password, email, two-factor, passkeys, linked
  accounts, account deletion).

## Schema

| Model | Field | Notes |
|---|---|---|
| `user` | `role` | `"user"` by default; returned in user records |
| `user` | `banned` | `False` by default; returned in user records |
| `user` | `ban_reason`, `ban_expires_at` | Admin endpoints only |
| `session` | `impersonated_by` | The admin's user id; returned in session records |

None of these can be set by users: `update_user` and the sign-up inputs refuse them.
`role` and `banned` are nullable columns (NULL reads as `"user"` and not banned), so
the plugin can be added to a database that already has users.

## Endpoints

Every endpoint needs an admin's session: a user whose role is in `admin_roles` or
whose id is in `admin_user_ids`. API keys and OAuth tokens are refused (session-only
endpoints, `UNAUTHENTICATED`), a signed-in user who is not an admin gets `FORBIDDEN`,
and so does an impersonation session. `{user_id}` is the target user.

| Endpoint | Route | Notes |
|---|---|---|
| `list_users` | GET `/admin/users` | `search` (part of the email or name), `sort_by` (`created_at` or `email`), `sort_direction`, `limit` (up to 100), `offset`; returns `{users, total}` |
| `create_user` | POST `/admin/users` | `{email, password?, name?, role?, email_verified?}`; emits `user.created` |
| `get_user` | GET `/admin/users/{user_id}` | |
| `remove_user` | DELETE `/admin/users/{user_id}` | Fresh session; runs the user delete hooks; emits `user.deleted` |
| `set_user_role` | POST `/admin/users/{user_id}/role` | `{role}`; emits `user.role_changed` |
| `set_user_password` | POST `/admin/users/{user_id}/password` | Fresh session; `{new_password}`; signs the user out; emits `password.changed` |
| `ban_user` | POST `/admin/users/{user_id}/ban` | `{reason?, expires_in?}`; signs the user out; emits `user.banned` |
| `unban_user` | POST `/admin/users/{user_id}/unban` | Emits `user.unbanned` |
| `list_user_sessions` | GET `/admin/users/{user_id}/sessions` | Shows `impersonated_by` |
| `revoke_user_sessions` | POST `/admin/users/{user_id}/sessions/revoke` | `{session_id?}`: one session, or all |
| `impersonate_user` | POST `/admin/users/{user_id}/impersonate` | Fresh session; emits `admin.impersonation_started` |
| `stop_impersonating` | POST `/admin/stop-impersonating` | Any impersonation session; emits `admin.impersonation_stopped` |

Admins cannot ban, remove or impersonate themselves.

## Bans

A banned user:
- **can't sign in** by any method. The check runs after the credential check, so a
  wrong password still gets `INVALID_CREDENTIALS`, and a right one gets
  `ADMIN_USER_BANNED`.
- **loses every session** when the ban is set.
- **can't use API keys or OAuth tokens:** a principal check rejects any credential
  whose user is banned with `ADMIN_USER_BANNED`. The flag is cached per user for up
  to 5 seconds in each process; a ban or unban through this process takes effect at
  once.

A ban with `expires_in` ends by itself. Requests treat it as over at once; the stored
flag is cleared at the user's next sign-in, so a GET never writes.

With `sessions.cookie_cache` on, a cached session still reaches the principal check,
so a banned user is refused there. That check costs one user lookup per request, at
most every 5 seconds per user.

## Impersonation

`impersonate_user` creates a session of the target with `impersonated_by` set to the
admin's id, lasting `impersonation_expires_in`. The browser's session cookie now holds
the new session, and the admin's own session token moves to the signed HttpOnly
cookie `gotauth.admin_session`, which lasts no longer than the impersonation. A caller
using a bearer session gets the new token in the response instead.

`stop_impersonating` revokes the impersonation session and, when the admin cookie
holds a session of the same admin that is still valid, signs the browser back in as
the admin (`{"restored": true}`). Otherwise the browser is signed out. Signing out
during an impersonation ends the admin's own session too, and emits
`admin.impersonation_stopped`.

An impersonation session:
- ends after `impersonation_expires_in`, however often it is used;
- ends as soon as its admin is no longer an admin, is banned or is deleted;
- can't call admin endpoints, or the endpoints in `impersonation_blocked`
  (`ADMIN_IMPERSONATION_BLOCKED`);
- otherwise acts as the user. Every event emitted from it carries its session id as
  `principal.credential_id`, and `list_user_sessions` shows `impersonated_by`, so
  audits can tell the admin's actions apart.

With `sessions.cookie_cache` on, a revoked session can still be presented until its
cache cookie expires (C3). The plugin remembers which sessions were impersonations, so
an ended impersonation stays refused in the process that saw it, and admin endpoints
refuse any session whose row is gone.

## Errors

| Code | Status | When |
|---|---|---|
| `ADMIN_USER_BANNED` | 403 | Sign-in, request or impersonation of a banned user |
| `ADMIN_CANNOT_TARGET_SELF` | 400 | Banning, removing or impersonating yourself |
| `ADMIN_CANNOT_IMPERSONATE_ADMIN` | 403 | Impersonating an admin without `allow_impersonating_admins` |
| `ADMIN_NOT_IMPERSONATING` | 400 | `stop_impersonating` from an ordinary session |
| `ADMIN_IMPERSONATION_BLOCKED` | 403 | An `impersonation_blocked` endpoint called while impersonating |
