# P3: Passkeys (WebAuthn)

| | |
|---|---|
| Lane / wave | Plugins / **Wave 3** (parallel) |
| Size | M |
| Depends on | C3; C1 (`complete_sign_in`) |
| Can start | after M2, or earlier against `gotauth.testing` |
| Write scope | `src/gotauth/plugins/passkey/**`, `tests/plugins/passkey/**`, `changes/P3.*.md` |
| Allowed new deps | runtime: `webauthn` (existing `passkey` extra, lazy import); dev: none |

## Goal
A `passkey()` plugin (id `"passkey"`, `from gotauth.plugins.passkey import passkey`): add passkeys to a signed-in account and sign in usernameless with discoverable credentials. py_webauthn verifies the ceremonies; GotAuth owns challenges, storage and sessions.

## Build
- Model `passkey` (`pky`): `user_id` -> user (cascade, index), `credential_id` (unique, base64url), `public_key` (text, base64url COSE, `returned=False`), `sign_count` (integer), `transports` (string_list), `device_type` (`single_device` | `multi_device`), `backed_up` (boolean), `name` (optional), `created_at`, `last_used_at` (optional).
- Config: `rp_id` (host of `base_url`), `rp_name`, `origins` (origin of `base_url` + exact `trusted_origins`; wildcards ignored), `user_verification` "preferred", `reject_sign_count_regression` True.
- Endpoints (ids verb first):
  - `get_passkey_registration_options` POST `/passkey/register/options`, session. `residentKey: required`, `attestation: none`, `excludeCredentials` = the user's passkeys, user handle = UTF-8 bytes of the user id (opaque string, no PII).
  - `verify_passkey_registration` POST `/passkey/register/verify`, session. `{response, name?}`; emits `passkey.added`.
  - `get_passkey_sign_in_options` POST `/passkey/sign-in/options`, none. Empty `allowCredentials` (usernameless, works with conditional UI).
  - `sign_in_passkey` POST `/passkey/sign-in/verify`, none. Find by credential id, require `userHandle` == owner, verify, compare-and-set `sign_count` + `last_used_at`, then `ctx.auth.complete_sign_in(ctx, user, method="passkey")`.
  - `list_passkeys` GET `/passkeys`, session. `rename_passkey` PATCH `/passkeys/{id}`, session. `delete_passkey` DELETE `/passkeys/{id}`, session, fresh: `LAST_SIGN_IN_METHOD` if it is the only passkey and the user has no `account` row; emits `passkey.removed`. Another user's id -> `NOT_FOUND`.
- Challenges: `crypto.random_token(nbytes=32)`, stored as a `verification` row (`identifier` `passkey:register:<user_id>` or `passkey:sign_in`, `value_hash` = `hash_token(challenge)` by the long-token rule (2.1), 5 minutes) and bound to the browser by the cookie `gotauth.passkey_challenge` (row id signed with purpose `"passkey_challenge"`, Max-Age 300, named via `cookie_name`). Verify consumes it first: `delete(id, value_hash of the clientDataJSON challenge, expires_at > now) == 1`.
- Sign count: both counts > 0 and received <= stored -> reject and log a warning. 0/0 (synced passkeys) is accepted.
- Errors: `PASSKEY_CHALLENGE_INVALID` (400), `PASSKEY_VERIFICATION_FAILED` (401; also for unknown credential ids, so ids are not probed), `PASSKEY_ALREADY_REGISTERED` (409).
- Rate limits: the 10.2 default (`/passkey/*` 10 per 60s) covers every endpoint; no plugin rule needed.
- Ship `gotauth.plugins.passkey.testing.SoftAuthenticator`: "none" attestations and ES256 assertions built with `cryptography` (CBOR via `webauthn`'s own dependency), so tests need no browser. G4 part 2 uses it too.

## Acceptance tests
- Register, then sign in with `SoftAuthenticator` via `make_client`; `get_session` returns the user.
- Replayed response -> `PASSKEY_CHALLENGE_INVALID`; expired (`fake_clock.advance("6m")`) and missing or foreign challenge cookie -> same.
- Wrong origin, wrong `rp_id` hash, wrong `type`, bad signature, another user's `userHandle` -> `PASSKEY_VERIFICATION_FAILED`.
- Sign-count regression rejected; 0/0 accepted.
- With P2 on, passkey sign-in creates a session without a 2FA challenge.
- Only sign-in method -> `LAST_SIGN_IN_METHOD`; another user's passkey -> `NOT_FOUND`.
- Works for an imported user whose id is a UUID string (section 1).
- No response includes `public_key`. Hypothesis: any byte flip in authenticator data, client data or signature fails.

## Out of scope
Attestation verification and authenticator allow-lists, passkey-first sign-up, UI (D2), browser tests with a CDP virtual authenticator (Q2).

## Notes
- Target py_webauthn 2.x (2.2 docs accept `expected_origin` as a string or list). Check the current release and record it in the README.
- `rp_id` must be a registrable suffix of every origin: check at construction (`ConfigError`). Changing `rp_id` later orphans all passkeys; say so in the README.
