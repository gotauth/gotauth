# gotauth.sessions

Sessions, session cookies and bearer session tokens. Work package C3.

## What it does

- `session_service(config, *, secondary_storage=None)` builds the `SessionService`
  that `GotAuth` uses for `ctx.sessions`.
- `sessions_plugin()` adds the `get_session`, `list_sessions`, `revoke_session` and
  `revoke_other_sessions` endpoints and the resolver for `Bearer gas_...` tokens.
  `GotAuth` installs it before any other plugin.
- `memory_secondary_storage()` and `redis_secondary_storage(url)` implement
  `SecondaryStorage`. The Redis one needs the `redis` extra.

## Tokens

Session tokens look like `gas_<random>`. Only `crypto.hash_token(token)` is stored.
Every sign-in creates a new token, so a token sent with the sign-in request is never
reused (session fixation).

## Expiry

| Setting | Default | Meaning |
|---|---|---|
| `sessions.expires_in` | 7d | Lifetime with "remember me" |
| `sessions.short_expires_in` | 1d | Lifetime without it; the cookie has no Max-Age |
| `sessions.update_age` | 1d | A read at least this long after the last refresh extends the session |

A refresh is a compare-and-set on `updated_at`, so concurrent reads refresh once.
`expires_at` never moves backwards. Expired rows are deleted when they are read.

## Cookie cache and its revocation delay

With `sessions.cookie_cache.enabled`, a signed `session_data` cookie holds the session
and user for `cookie_cache.max_age` (5 minutes by default). While it is valid, reads
skip the database. **A revoked session keeps working in that browser until the cache
cookie expires, up to `max_age`.** Keep `max_age` short, or leave the cache off, if
revocation must be immediate. Bearer requests never carry the cache cookie.

The cache is bound to its own session token through a hash of the token, so it cannot
be paired with another session. It is skipped when it would be larger than 3.5 KB.

## Secondary storage

When `GotAuth(secondary_storage=...)` is set, sessions are cached under
`session:<token hash>` and removed on revocation. An entry lives at most 5 minutes (and
never past `expires_at`), which bounds how long a direct write to a session row, such as
a plugin changing a field, can go unseen. Expiry and sliding refresh are always decided
on the database row, never on a cached copy.

## Bearer requests

`get` writes cookies only when the token is the request's own session cookie. A request
with `Authorization: Bearer gas_...` or `X-Api-Key: gas_...` never changes the
browser's cookie session.
