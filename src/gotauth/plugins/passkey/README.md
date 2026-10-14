# gotauth.plugins.passkey

Passkeys (work package P3): add passkeys to a signed-in account and sign in with
them, usernameless (discoverable credentials, works with conditional UI).
py_webauthn verifies the ceremonies; GotAuth owns the challenges, the storage and the
sessions. Built against `webauthn` 3.0.1 (checked 2026-10-14); needs
`pip install "gotauth[passkey]"`.

```python
from gotauth.plugins.passkey import passkey

auth = GotAuth(..., plugins=[passkey()])
```

Options:
- **`rp_id`:** the host of `base_url` by default. It must be that host or a parent domain of every origin, checked before the first request (`ConfigError`).
  - The origins are `base_url`'s plus the exact `trusted_origins`, normalized as browsers report them (lower case, no default port); wildcard origins are ignored.
  - **Changing `rp_id` later orphans every registered passkey.**
- **`rp_name`:** what browsers show; `rp_id` by default.
- **`user_verification`:** `"preferred"` by default. A sign-in without user verification (a security key without a PIN) is refused unless this is `"discouraged"`. Possession alone is one factor, and two-factor lets passkey sign-ins through. With `"discouraged"`, also remove `"passkey"` from two-factor's `skip_for_methods`.
- **`reject_sign_count_regression`:** `True` by default.

## Endpoints

| Endpoint | Auth | What |
|---|---|---|
| `POST /passkey/register/options` | session | Options for `navigator.credentials.create()`. Resident key required, no attestation, your passkeys excluded. The user handle is the user id's bytes (no personal data) |
| `POST /passkey/register/verify` | session | `{response, name?}`: stores the passkey, emits `passkey.added`. `PASSKEY_ALREADY_REGISTERED` (409) for a known credential |
| `POST /passkey/sign-in/options` | none | Options for `navigator.credentials.get()` with an empty allow list |
| `POST /passkey/sign-in/verify` | none | `{response, remember_me?}`: signs in through `complete_sign_in` with method `passkey`. Two-factor skips passkeys by default |
| `GET /passkeys` | session | Your passkeys, never the public keys |
| `PATCH /passkeys/{id}` | session | `{name}` |
| `DELETE /passkeys/{id}` | fresh session | Emits `passkey.removed`. `LAST_SIGN_IN_METHOD` (409) for the only passkey of an account without a set password or a social login. Deletes for one user run one at a time |

Another user's passkey id answers 404. The registry's `webauthn.ts` helpers send and
read these JSON shapes.

## Security

- **Challenges:**
  - 32 random bytes, stored hashed as a `verification` row for 5 minutes
  - bound to the browser by the signed cookie `gotauth.passkey_challenge`, with one slot each for registration and sign-in, so starting one keeps the other
  - one pending registration challenge per user; expired sign-in challenges are removed when new ones are made
  - consumed before the response is verified, so a response works once, only in the browser that asked, for the same ceremony
- **Verification:** py_webauthn checks the origin, the `rp_id` hash, the type, the signature and user presence (and verification, when required).
- **Ownership:** the `userHandle` must be the passkey's owner.
- **No probing:** unknown credentials and wrong owners answer `PASSKEY_VERIFICATION_FAILED` (401), like a bad signature.
- **Sign counts:** a count that did not go up is refused and logged as a possibly cloned authenticator. Synced passkeys that always report 0 are accepted.
- **Rate limits:** `/passkey/*` allows 10 requests per minute per IP (CONTRACTS 10.2).

## Tests without a browser

`gotauth.plugins.passkey.testing.SoftAuthenticator` creates "none" attestations and
ES256 assertions in memory:

```python
device = SoftAuthenticator(origin="http://localhost:8000")
options = (await http.post("/passkey/register/options")).json()
await http.post("/passkey/register/verify", json={"response": device.create(options)})
options = (await http.post("/passkey/sign-in/options")).json()
await http.post("/passkey/sign-in/verify", json={"response": device.get(options)})
```

Like a browser, it honors `rpId`, `allowCredentials` and `excludeCredentials`.
`counting=False` behaves like a synced passkey, `backed_up=True` reports a
multi-device credential, and `user_verified=False` behaves like a security key
without a PIN.
