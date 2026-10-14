# gotauth.plugins.magic_link

Passwordless sign-in (work package P4). Two plugins share this package:
- **`magic_link()`** emails a sign-in link.
- **`email_otp()`** emails a 6-digit code that signs in, verifies an email address, or resets a password.

Both need an email sender, and both follow the enumeration rules of CONTRACTS 9.1.

```python
from gotauth.plugins.magic_link import email_otp, magic_link

auth = GotAuth(..., plugins=[magic_link(), email_otp()])
```

Options for both:
- **`allow_sign_up`:** `True` by default; the first sign-in creates the account, with its email verified.
- **`expires_in`:** `"10m"` for links, `"5m"` for codes.
- **`send_cooldown`:** `"60s"`; a repeat request inside it answers the same and sends nothing.

## Magic link

1. **`POST /magic-link/send`** `{email, callback_url="/", error_callback_url?}`.
   - It always answers `{status: "ok"}`.
   - The URLs must pass the redirect rules (CONTRACTS 10.1), or the answer is `INVALID_REQUEST` and nothing is sent.
   - With `allow_sign_up=False`, an unknown email gets no link.
2. **The link** is `GET /magic-link/verify?token=gav_...`.
   - It works once, inside its lifetime.
   - It signs in (method `magic_link`) and redirects to `callback_url`. With two-factor on, it appends `?challenge=two_factor`.
   - **Failures** redirect to `error_callback_url?error=<code>` when one was given. Otherwise they answer `TOKEN_INVALID` or `TOKEN_EXPIRED`.

**Mail scanners.** Some corporate mail scanners open links before the user does, which
uses the token. If your users hit this, show a confirm page that posts the token, or
use the email code instead.

## Email code

1. **`POST /email-otp/send`** `{email, type}`, where `type` is `sign_in`, `verify_email` or `reset_password`.
   - It always answers `{status: "ok"}`.
   - A code goes out only when the type applies:
     - `sign_in`: the account exists, or sign-up is allowed
     - `verify_email`: the account exists and is unverified
     - `reset_password`: the account exists
2. **`POST /email-otp/verify`** `{email, otp, type, new_password?}`:
   - `sign_in`: signs in (method `email_otp`), creating the account if allowed.
   - `verify_email`: marks the email verified and emits `user.email_verified`.
   - `reset_password`:
     - sets the password (it must pass the email/password length rules and `password_check`)
     - ends every session
     - emits `password.reset`

Every failure answers `EMAIL_OTP_INVALID` (400), unknown emails included. A code works
once and only for its type and email. Five wrong codes delete it: the count is kept
with `ctx.on_failure` (CCR 012).

## Security

- **Stored only as hashes:**
  - link tokens by the long-token rule
  - codes by the short-code rule, together with their identifier, so two users can hold the same code
- **Timing:** the code or link is created and sent after the reply, for every email alike, so the response time says nothing about the account.
- **Rate limits:** `/magic-link/*` and `/email-otp/*` allow 5 requests per minute per IP. The send endpoints also allow 10 per 15 minutes per email, across IPs (CONTRACTS 10.2).
- **New accounts** are created through `auth.create_user_record`, so user hooks run and `user.created` is emitted.
