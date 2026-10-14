# gotauth.plugins.two_factor

Two-factor authentication (work package P2): TOTP, single-use backup codes and an
optional email OTP fallback. A sign-in interceptor requires the second step for every
sign-in method, except those in `skip_for_methods` (a passkey already counts as two
factors).

```python
from gotauth.plugins.two_factor import two_factor

auth = GotAuth(..., plugins=[two_factor()])
```

Options:
- `issuer`: the name authenticator apps show. The default is the host of `base_url`.
- `backup_code_count`: 10 by default.
- `trust_device_max_age`: `"30d"` by default.
- `skip_for_methods`: `("passkey",)` by default.
- `email_otp`: `False` by default. Turning it on needs an email sender.
- `enforce(user) -> bool`: may be async. When it returns true, a user without two-factor must set it up during sign-in, and can't turn it off.

## Setup

1. **`POST /two-factor/enable`** `{password?}` (fresh session; the password is needed if the user has one). It returns `{totp_uri, backup_codes}`, shown once.
   - Show `totp_uri` as a QR code.
   - Two-factor stays off until the next step.
2. **`POST /two-factor/verify-totp`** `{code}` with the session confirms it, sets `user.two_factor_enabled` and emits `two_factor.enabled`.

## Sign-in

With two-factor on, a sign-in answers `{challenge: {type: "two_factor", methods}}` and
sets the challenge cookie, not a session. The client then sends one of:

| Endpoint | Body |
|---|---|
| `POST /two-factor/verify-totp` | `{code, trust_device?}` |
| `POST /two-factor/verify-backup-code` | `{code, trust_device?}`; each code works once |
| `POST /two-factor/send-otp`, then `POST /two-factor/verify-otp` | `{code, trust_device?}` (with `email_otp=True`); 5 minutes, 5 tries |

A valid code finishes the sign-in through `auth.finish_challenge`. The session keeps
the `remember_me` given at sign-in.

**Trusting a device.** `trust_device: true` sets `gotauth.two_factor_trust` (signed,
HttpOnly, 30 days), so that device skips the second step. The cookie is bound to the
user's two-factor setup: turning two-factor off and on again drops every trusted device.

**Enforced setup.** For an enforced user without two-factor, the challenge type is
`two_factor_setup` with `methods: ["totp"]`. `enable` and `verify-totp` then accept the
challenge cookie instead of a session, and the confirming code also finishes the
sign-in.

## Managing it

- **`POST /two-factor/disable`** `{password?}`: fresh session. Emits `two_factor.disabled`. `FORBIDDEN` for enforced users.
- **`POST /two-factor/regenerate-backup-codes`**: fresh session. Returns new codes, shown once; the old ones stop working.

## Security

- **Stored only encrypted or hashed:** the TOTP secret is encrypted (purpose `two_factor_secret`). Backup codes and email codes are stored only as hashes, and an email code is hashed with its identifier, so two users can hold the same code.
- **Codes work once:**
  - a TOTP time step is accepted once, and never an earlier step than the last one used
  - a backup code is claimed with a compare-and-set, so it works once even under concurrent requests
  - a wrong email code is counted, and the code is deleted at the 5th failure
- **Rate limits:** besides the 5 per minute per IP on `/two-factor/*`, the verify endpoints allow 10 tries per user per 15 minutes, across IPs.
- **Challenge cookie problems** answer `TOKEN_INVALID` or `TOKEN_EXPIRED` (after 10 minutes).
- **Errors:** `TWO_FACTOR_INVALID_CODE` (401), `TWO_FACTOR_NOT_ENABLED` (400), `TWO_FACTOR_ALREADY_ENABLED` (409), `TWO_FACTOR_CONFLICT` (409).

TOTP uses SHA1, 6 digits and 30-second steps, which every authenticator app supports.
