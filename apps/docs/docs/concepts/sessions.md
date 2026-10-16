# Sessions

A session is a row in `auth_session`. The browser holds its token in a cookie; the
database holds only a hash of it, so a database leak gives no working sessions.

## The cookie

- Name: `gotauth.session_token`; `__Secure-gotauth.session_token` when `base_url` is
  `https`. The prefix comes from `advanced={"cookie_prefix": ...}`.
- `HttpOnly`, `SameSite=Lax`, `Secure` on https, path `/`.
- The token looks like `gas_...` and is random; it is never stored.
- Sign-in always creates a new token, so a token planted before sign-in is useless
  (session fixation).

## Lifetimes

| Setting | Default | Meaning |
|---|---|---|
| `expires_in` | `"7d"` | How long a session lasts ("keep me signed in") |
| `short_expires_in` | `"1d"` | The server-side lifetime with `remember_me=false`; the cookie also ends with the browser |
| `update_age` | `"1d"` | Sliding refresh: a session used after this long gets a new expiry |
| `absolute_lifetime` | `"30d"` | No session outlives this from its creation, however often it slides |
| `fresh_age` | `"1d"` | Sensitive actions (changing the password or email, deleting the account) need a session younger than this |

<!-- sample: skip: a configuration fragment -->
```python
auth = GotAuth(..., sessions={"expires_in": "14d", "fresh_age": "1h"})
```

## Bearer sessions

Native and CLI clients can send `Authorization: Bearer gas_...` instead of the cookie
(`allow_bearer`, on by default). They get the token from sign-in when
`sessions={"expose_token": True}`; browsers never need it.

## Listing and revoking

`GET /sessions` lists the user's sessions with the current one marked;
`POST /sessions/revoke` ends one, `POST /sessions/revoke-others` all the others.
A password reset ends every session (`revoke_sessions_on_password_reset`, on by default);
a password change ends the other sessions when asked (`revoke_other_sessions: true`).

## The cookie cache

With `sessions={"cookie_cache": {"enabled": True}}`, GotAuth also sets a signed
`session_data` cookie and reads the session from it, skipping the database for up to
`cookie_cache.max_age` (5 minutes by default).

!!! warning "Revocation waits for the cache"
    A revoked session keeps working in a browser that holds a cached copy, until that
    copy expires: up to `cookie_cache.max_age`. Keep the cache off, or its `max_age`
    short, if a revoked session must stop at once. Principal checks (such as the admin
    plugin's ban check) still run on every request.

## Secondary storage

`secondary_storage=redis_secondary_storage(...)` (from `gotauth.sessions`, with the `redis`
extra) keeps session lookups and rate-limit counters in
Redis. Sessions stay in the database; Redis is a cache in front of it.
