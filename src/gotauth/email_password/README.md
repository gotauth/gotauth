# gotauth.email_password

Sign-up, sign-in, email verification, password reset and account management by email
and password. Work package C2. `GotAuth` installs `email_password_plugin()` when
`email_password.enabled` is true (the default).

## Endpoints

| Endpoint | Path | Auth |
|---|---|---|
| `sign_up_email` | POST `/sign-up/email` | none |
| `sign_in_email` | POST `/sign-in/email` | none |
| `sign_out` | POST `/sign-out` | session |
| `send_verification_email` | POST `/send-verification-email` | none |
| `verify_email` | GET `/verify-email?token=...` | none (one-time link) |
| `request_password_reset` | POST `/request-password-reset` | none |
| `reset_password` | POST `/reset-password` | none |
| `change_password` | POST `/change-password` | fresh session |
| `change_email` | POST `/change-email` | session |
| `update_user` | PATCH `/user` | session |
| `delete_user` | DELETE `/user` (JSON body) | fresh session |

Every sign-in goes through `auth.complete_sign_in`, so two-factor and other sign-in
checks apply without changes here.

## Account enumeration

These endpoints never reveal whether an email has an account:

- `request_password_reset` and `send_verification_email` always answer
  `{"status": "ok"}`.
- With `require_email_verification=True` (the default), sign-up with an existing email
  answers `{"status": "verification_sent"}` like a new one, and the owner gets a
  `sign_up_existing_account` email. The password is hashed in both cases.
- Sign-in with an unknown email runs a dummy password check and answers
  `INVALID_CREDENTIALS`, the same as a wrong password.
- `change_email` to an address that is taken answers like any other change.

**Trade-off:** with `require_email_verification=False` the user is signed in at once, so
sign-up with an existing email must answer `USER_ALREADY_EXISTS`. That reveals the
account. Keep verification on if that matters.

Email delivery errors on these endpoints are logged (kind and error type only) and never
change the answer. Off localhost, delivery runs in the background so response time does
not reveal the account either.

## Tokens

Verification, email change and reset tokens look like `gav_<random>`. Only their hash is
stored. Each token is single use, and a new token replaces older ones of the same kind
for the same user. Lifetimes: `verify_token_expires_in` (24h) and
`reset_token_expires_in` (1h). A verification token only verifies the address it was
sent to. Changing the email or the password cancels pending reset links, and changing
the email also cancels pending verification links for the old address.

Reset links go to the app's `redirect_to` page with `?token=gav_...`; that page calls
`POST /reset-password`. There is no GET reset endpoint.

## Passwords

- Length between `min_password_length` (8) and `max_password_length` (128), else
  `PASSWORD_TOO_SHORT` or `PASSWORD_TOO_LONG`. At sign-in an over-long password is
  rejected as `INVALID_CREDENTIALS` without hashing it.
- Hashes from an older algorithm or weaker parameters (for example imported bcrypt) are
  upgraded on the next successful sign-in.
- A password reset revokes every session of the user unless
  `revoke_sessions_on_password_reset=False`, and sends a `security_notice` email.
