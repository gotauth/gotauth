# C2: Email and password flows

| | |
|---|---|
| Lane / wave | Core / **Wave 1** |
| Size | M (2 agent-days) |
| Depends on | M0 |
| Can start | after M0 |
| Write scope | `src/gotauth/email_password/**`, `tests/email_password/`, `changes/C2.*.md` |
| Allowed new deps | none |

## Goal
Sign-up, sign-in, verification, reset and account management by email and password, with no account enumeration (9.1). Every sign-in goes through `ctx.auth.complete_sign_in`, so 2FA and bans apply later without changes here.

## Build
- Entry point (13.2): `email_password_plugin(config: ResolvedConfig) -> Plugin` (id `email_password`, installed by C1 when `email_password.enabled`) with the C2 rows of 13.1; ids, methods, paths, `auth`, `fresh_session` and outputs exactly as listed. `requires_email` = `require_email_verification`. Inputs are JSON bodies (C1 enforces the content type):
  - `sign_up_email` `{email, password, name?, image?, callback_url?, remember_me=true}`. Creates `user` and `account` (`provider_id="credential"`, `account_id` = user id). Verification required: send `verify_email`, no session, `StatusOut("verification_sent")`; an existing email gets the same body, a `sign_up_existing_account` email, and its password is still hashed. Verification off: existing -> USER_ALREADY_EXISTS; else `complete_sign_in` when `auto_sign_in`, otherwise StatusOut. A UniqueViolation from a concurrent sign-up gets the same response as an existing email.
  - `sign_in_email` `{email, password, remember_me=true}`. Unknown email -> `verify_password(pw, "")` then INVALID_CREDENTIALS; wrong password -> same. Unverified with verification required -> EMAIL_NOT_VERIFIED, only after a correct password. On success, rehash if `needs_rehash` (compare-and-set on the old hash), then `complete_sign_in(ctx, user, method="password", remember_me=...)`. Never call `ctx.sessions.create` directly.
  - `sign_out`: revoke the current session, `clear_cookies`, emit `sign_out`.
  - `send_verification_email` `{email, callback_url?}` -> always `StatusOut("ok")`.
  - `verify_email` (query `token`, `callback_url?`; a GET that writes, allowed as a one-time email link): consumes `verify_email:<user_id>` (sets `email_verified`) or `change_email:<user_id>` (sets `email` = `data.new_email`, verified; taken -> USER_ALREADY_EXISTS). With `callback_url`: 302 there, or there with `?error=<CODE>`. Without: StatusOut or error JSON.
  - `request_password_reset` `{email, redirect_to}` -> always `StatusOut("ok")`. Users with a credential account get `reset_password` with url = `redirect_to` + `?token=gav_...` (9: the app's page then calls `reset_password`; there is no GET reset endpoint).
  - `reset_password` `{token, new_password}`: consume `reset_password:<user_id>`, set the hash, revoke all sessions if `revoke_sessions_on_password_reset` (default True), send `security_notice`, emit `password.reset`.
  - `change_password` `{current_password, new_password, revoke_other_sessions=false}`: emit `password.changed`.
  - `change_email` `{new_email, callback_url?}`: token to the new address (`change_email:<user_id>`, `data.new_email`); same StatusOut if the address is taken; `security_notice` to the old one.
  - `update_user` `{name?, image?}` -> UserOut (email changes only via `change_email`); emit `user.updated`.
  - `delete_user` DELETE `/user`, JSON body `{password?}` (required and verified when the user has a credential account): `ctx.auth.delete_user(ctx, user.id)` (C1 runs the database hooks, cascades and emits `user.deleted`), then `clear_cookies`.
- Verification tokens (2.1, long-token rule): `crypto.random_token("gav_")`; only `hash_token` in `verification.value_hash`; identifiers as above; a new token deletes older rows with the same identifier; expiry `verify_token_expires_in` (24h) or `reset_token_expires_in` (1h). Consume: find by hash, check the identifier kind, then `delete([id, value_hash, expires_at > now]) == 1`; otherwise TOKEN_INVALID, or TOKEN_EXPIRED if the row exists but expired.
- Passwords: `min_password_length` (8) / `max_password_length` (128) -> PASSWORD_TOO_SHORT / PASSWORD_TOO_LONG when set; at sign-in an over-long password gets INVALID_CREDENTIALS without hashing. Emails trimmed, lower-cased, simple syntax check, max 254 chars. Redirect params via `gotauth.core.validate_redirect` (local stub with `# TODO(C1)` until C1 merges).
- Email data keys follow D1's table. `url`: relative to the auth mount for verify links (`/verify-email?token=...&callback_url=...`; D1 prefixes `base_url + base_path`), absolute for reset links. Delivery runs in the background off localhost (9); render or send errors on enumeration-protected endpoints are logged and swallowed.
- Per-email rate limits on `/sign-in/email` and `/request-password-reset` are C1 defaults (10.2); nothing to add here.
- Events: `user.created`, `user.updated`, `sign_in.failed` (`{method, reason}`), `sign_out`, `user.email_verified`, `user.email_changed`, `password.changed`, `password.reset`.
- New users are created only through `ctx.auth.create_user_record(ctx, data)` (CONTRACTS 13), so user database hooks run and `user.created` is emitted.

## Acceptance tests
- With `make_context`, `call_endpoint`, `fake_mailer`, `fake_sessions`, `fake_clock`.
- Enumeration: byte-identical bodies for existing vs unknown email on sign-up (verification on), `send_verification_email`, `request_password_reset`; unknown email and wrong password give identical sign-in errors; a spy shows the dummy hash ran.
- 20 concurrent `reset_password` calls with one token -> exactly 1 success; expired -> TOKEN_EXPIRED; wrong kind -> TOKEN_INVALID; no raw `gav_` value in any row.
- Reset revokes all sessions by default and none with the flag off.
- A bcrypt or low-cost scrypt hash is upgraded after sign-in. `complete_sign_in` is called with `method="password"`.
- `delete_user` with a JSON body: wrong password -> INVALID_CREDENTIALS; success goes through `ctx.auth.delete_user` (fake records the call) and clears cookies.
- Hypothesis: length boundaries; passwords never appear in responses, events or logs (caplog).
- Endpoint objects match `CORE_ENDPOINTS` for the C2 rows; untrusted redirect params -> INVALID_REQUEST.

## Out of scope
- Sessions and cookies (C3); pipeline, origin checks, rate limits, user deletion internals (C1); templates and senders (D1); magic link and OTP (P4); 2FA (P2).

## Notes
- `delete_user` never deletes rows itself: `ctx.auth.delete_user` is the only path, so plugin and app hooks always run.
