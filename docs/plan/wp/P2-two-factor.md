# P2: Two-factor authentication

| | |
|---|---|
| Lane / wave | Plugins / **Wave 3** (parallel) |
| Size | M |
| Depends on | C2, C3; C1 (`complete_sign_in`, `finish_challenge`, challenge cookie) |
| Can start | after M2, or earlier against `gotauth.testing` |
| Write scope | `src/gotauth/plugins/two_factor/**`, `tests/plugins/two_factor/**`, `changes/P2.*.md` |
| Allowed new deps | none (TOTP and OTPs are in the crypto kit, section 8) |

## Goal
A `two_factor()` plugin (id `"two_factor"`, `from gotauth.plugins.two_factor import two_factor`): TOTP, single-use backup codes and an optional email OTP fallback, enforced for all sign-in methods by a `SignInInterceptor`.

## Build
- Model `two_factor` (`tfa`): `user_id` -> user (unique, cascade), `secret_enc` (`crypto.encrypt`, purpose `"two_factor_secret"`), `backup_code_hashes` (json list), both `returned=False`; `verified_at` (null = unconfirmed), `last_used_step` (integer), `version` (integer, compare-and-set counter), `created_at`. User field `two_factor_enabled` (default False, `input=False`).
- Config: `issuer` (host of `base_url`), `backup_code_count` 10, `trust_device_max_age` "30d", `skip_for_methods` ("passkey",), `email_otp` False, `enforce(user) -> bool` (optional). `email_otp=True` sets `Plugin.requires_email`.
- Endpoints (ids verb first; 5 per 60s per IP + path from 10.2):
  - `enable_two_factor` POST `/two-factor/enable`, session, fresh. `{password?}`, checked for users with a `credential` account. `TWO_FACTOR_ALREADY_ENABLED` if on. Returns `{totp_uri, backup_codes}` once; inactive until a code is verified.
  - `verify_totp` POST `/two-factor/verify-totp`, optional. `{code, trust_device}`. With a `gotauth.challenge` cookie: answers the sign-in challenge; else with a session: confirms setup, emits `two_factor.enabled`.
  - `verify_backup_code` POST `/two-factor/verify-backup-code`, none (challenge cookie).
  - `disable_two_factor` POST `/two-factor/disable`, session, fresh, `{password?}`; emits `two_factor.disabled`; `FORBIDDEN` if `enforce(user)`.
  - `regenerate_backup_codes` POST `/two-factor/regenerate-backup-codes`, session, fresh.
  - `send_two_factor_otp` / `verify_two_factor_otp` POST `/two-factor/send-otp` / `/verify-otp`, none, only if `email_otp`. Kind `"otp"`, `crypto.new_otp(6)`, identifier `two_factor_otp:<user_id>`, `value_hash` by the short-code rule (2.1), 5 minutes; wrong code: compare-and-set increment of `verification.attempts`, the 5th failure deletes the row.
- Interceptor: enabled, `method not in skip_for_methods`, no valid trust cookie -> `SignInChallenge("two_factor", ("totp", "backup_code"[, "email_otp"]))`. `enforce(user)` and not enabled -> type `"two_factor_setup"`; enable and `verify_totp` then accept the challenge cookie instead of a session.
- Challenge flow: read the pending challenge with `ctx.auth.read_challenge(ctx)` (CONTRACTS 13); None -> `TOKEN_INVALID`, past `exp` -> `TOKEN_EXPIRED`; the factor must be in `methods`. After a valid code, finish only with `ctx.auth.finish_challenge(ctx, satisfied="totp" | "backup_code" | "email_otp")`, which creates the session with the stored `remember_me`, clears the cookie and emits `sign_in.succeeded`. Never call `ctx.sessions.create`.
- Trust cookie `gotauth.two_factor_trust`: `crypto.sign` purpose `"trusted_device"` over `<user_id>.<tfa id>.<exp>`, HttpOnly, 30 days; bound to the row id, so re-enabling drops trusted devices.
- Replay: a TOTP step must be > `last_used_step` (compare-and-set `update`, section 3); backup codes use compare-and-set on `version`.
- Per-user cap in `Plugin.rate_limits` (10.2): `RateLimitRule(path="/two-factor/verify-*", window="15m", max=10, key="identifier", identifier=fn)`, where `fn` returns the `user_id` of a valid challenge cookie, else `ctx.principal.user_id`, else None. Per-IP limits alone allow distributed guessing.
- Errors: `TWO_FACTOR_INVALID_CODE` (401), `TWO_FACTOR_NOT_ENABLED` (400), `TWO_FACTOR_ALREADY_ENABLED` (409); challenge cookie problems use the core `TOKEN_INVALID` / `TOKEN_EXPIRED`, as `finish_challenge` does.

## Acceptance tests
- `load_vectors("totp")` + `fake_clock`: every RFC 6238 SHA1 vector verifies (6-digit code = last 6 digits).
- Flow: enable -> sign-in still unchallenged -> confirm -> sign-in gives `ChallengeOut`, no session cookie -> code -> session; `remember_me=False` at sign-in gives a browser-session cookie.
- Replay: same code twice in one step fails; step <= `last_used_step` fails.
- Hypothesis: each backup code verifies at most once (also under concurrent use); random strings never.
- Challenge cookie at 10m+ -> `TOKEN_EXPIRED`; tampered or missing -> `TOKEN_INVALID`.
- Trust cookie works on day 29; not day 31, another user, or after re-enable.
- `method="passkey"` skips the challenge; `skip_for_methods=()` does not.
- 11th verify attempt for one user across rotating IPs -> `RATE_LIMITED`.
- Email OTP: two users can hold the same code; 5 wrong then the right code fails.
- `email_otp=True` without an email sender off localhost -> `ConfigError`.
- DB dump: no plaintext secret, backup code or OTP. `update_user` cannot set the flag.

## Out of scope
Passkeys (P3), passwordless OTP (P4), SMS, UI (D2), admin 2FA reset (P6 follow-up).

## Notes
- Keep SHA1 / 6 digits / 30s for app compatibility.
- The test kit's `make_context` fakes `finish_challenge`; switch to C1's version after merge (`TODO(P2)`).
