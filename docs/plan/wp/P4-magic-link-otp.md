# P4: Magic link + email OTP

| | |
|---|---|
| Lane / wave | Plugins / **Wave 3** (cut-list item 4) |
| Size | S-M |
| Depends on | C3, D1 (kinds `magic_link`, `otp`); C1 (`complete_sign_in`) |
| Can start | after M2, or earlier against `gotauth.testing` (`fake_mailer`) |
| Write scope | `src/gotauth/plugins/magic_link/**`, `tests/plugins/magic_link/**`, `changes/P4.*.md` |
| Allowed new deps | none |

## Goal
Two plugins in one package, `magic_link()` and `email_otp()` (ids `"magic_link"`, `"email_otp"`; `from gotauth.plugins.magic_link import magic_link, email_otp`): passwordless sign-in by emailed link or 6-digit code, plus OTP email verification and password reset, under the enumeration rules of 9.1.

## Build
- No new models; both use `verification` (2.1). Both set `Plugin.requires_email=True` (9). Config: `allow_sign_up` True, `send_cooldown` "60s" (a repeat send inside it returns success without mailing).
- `send_magic_link` POST `/magic-link/send`, none. `{email, callback_url="/", error_callback_url?}`, URLs checked per 10.1. Token `crypto.random_token("gav_")`; row `identifier` `magic_link:<email>`, `value_hash` by the long-token rule (2.1), `expires_in` "10m", `data` = URLs; older rows for the identifier deleted; mail kind `"magic_link"`. Always the same `StatusOut`; unknown email with `allow_sign_up=False`: no row, no mail.
- `verify_magic_link` GET `/magic-link/verify?token=`, none. Consume with `delete(id, value_hash, expires_at > now) == 1`. Find the user, or create one (`email_verified=True`, `user.created`) only if `allow_sign_up`; mark an unverified user verified (`user.email_verified`). Then `complete_sign_in(ctx, user, method="magic_link")` and redirect to `callback_url` (append `challenge=two_factor` on `ChallengeOut`). Failure: redirect to `error_callback_url?error=<code>` if set, else `TOKEN_INVALID` / `TOKEN_EXPIRED`.
- `send_email_otp` POST `/email-otp/send`, none. `{email, type: "sign_in" | "verify_email" | "reset_password"}`. Same `StatusOut` always; mails kind `"otp"` only if the type applies (sign_in: user exists or `allow_sign_up`; verify_email: exists and unverified; reset_password: exists).
- `verify_email_otp` POST `/email-otp/verify`, none. `{email, otp, type, new_password?}`. OTP: `crypto.new_otp(6)`, row `identifier` `email_otp:<type>:<email>`, `value_hash` by the short-code rule (2.1: `hash_token(identifier + ":" + code)`), 5 minutes. Wrong code: compare-and-set increment of `verification.attempts`; the 5th failure deletes the row. Every failure, unknown email included, returns `EMAIL_OTP_INVALID` (400). On success:
  - `sign_in`: find or create as above, `complete_sign_in(method="email_otp")`.
  - `verify_email`: set `email_verified`, emit `user.email_verified`.
  - `reset_password`: `new_password` required (`PASSWORD_TOO_SHORT` / `PASSWORD_TOO_LONG` per `EmailPasswordConfig`), update the `credential` account hash, `revoke_all` sessions, emit `password.reset`.
- Rate limits: 10.2 defaults cover both: 5 per 60s per IP + path on `/magic-link/*` and `/email-otp/*`, and 10 per 15 minutes per `email` identifier on `/magic-link/send` and `/email-otp/send`. No plugin rule needed.
- Events: `user.created`, `user.email_verified`, `password.reset`, `sign_in.failed` (OTP failure, existing user); `sign_in.succeeded` comes from `complete_sign_in`.
- New users are created only through `ctx.auth.create_user_record(ctx, data)` (CONTRACTS 13), so user database hooks run and `user.created` is emitted.

## Acceptance tests
- `fake_mailer`: send -> `last("magic_link", email)` -> GET url -> session cookie and 302 to `callback_url`.
- Reused link -> `TOKEN_INVALID`; after `fake_clock.advance("11m")` -> rejected; two concurrent GETs -> one session.
- `callback_url="https://evil.example"` -> `INVALID_REQUEST`, no mail.
- Enumeration: known and unknown emails get byte-identical status and body on both send endpoints; with `allow_sign_up=False` the unknown email gets no mail and no user row.
- OTP works once; 5 wrong then the right code -> `EMAIL_OTP_INVALID`; a `verify_email` OTP fails for `sign_in`; two users can hold the same code.
- Hypothesis: for any guess sequence, at most one verify succeeds per OTP and none after 5 failures.
- `reset_password` revokes old sessions; the old password fails.
- 11 sends for one email across rotating IPs in 15 minutes -> the 11th gets `RATE_LIMITED`.
- No email sender off localhost -> `ConfigError` at construction.
- DB dump: no raw `gav_` token, no plain OTP.

## Out of scope
Templates and senders (D1), 2FA email OTP (P2), SMS, UI (D2).

## Notes
- Some corporate mail scanners prefetch links and would consume the token. Document it; a confirm-page option is a later follow-up.
- Off localhost, D1 delivers in the background (section 9), so send time does not depend on whether a mail goes out. Tests with a non-localhost `base_url` call `await auth.drain()` before reading `fake_mailer`.
