# gotauth.plugins.api_key

Scoped, revocable API keys for users, organizations and agents. Work package P1.

```python
from gotauth.plugins.api_key import api_key

auth = GotAuth(..., plugins=[api_key(allowed_scopes=["projects:read", "projects:write"])])
```

Options: `allowed_scopes` (the only scopes a key may carry; empty means none),
`default_expires_in`, `max_expires_in`, and `rate_limit=(max, window_seconds)` as the
default per-key limit.

## Keys

- A key looks like `gak_` + 43 characters. It is returned once, by `POST /api-keys`
  (or `issue_api_key`); only its hash is stored. Display it as `gak_<start>...`.
- Send it as `Authorization: Bearer gak_...` or `x-api-key: gak_...`.
- The principal has `via="api_key"` and exactly the key's scopes, never session rights,
  so keys cannot call session endpoints. Scopes are flat: `projects:write` does not grant
  `projects:read`.
- Organization keys act for no user (`user_id` is `None`, `organization_id` is set) and
  need the organization plugin's `has_permission` (`api_key: create/read/update/revoke`).
  Agent keys come from the agent plugin; they stop working when the agent is disabled.
- Revocation, disabling and expiry apply on the next request: there is no cache.

## Errors

| Code | Status | When |
|---|---|---|
| `API_KEY_INVALID` | 401 | Unknown or malformed key |
| `API_KEY_DISABLED` | 401 | Disabled (or its agent is) |
| `API_KEY_EXPIRED` | 401 | Past `expires_at` |
| `API_KEY_RATE_LIMITED` | 429 | Over the per-key limit; `Retry-After` is set |

## Rate limits and usage

Per-key limits use `GotAuth(secondary_storage=...)` when configured, so they hold across
processes. Without it each process counts on its own, so the effective limit is
`max x processes`. `last_used_at` is written at most once a minute.

## Server-side calls

`issue_api_key`, `verify_api_key` and `revoke_api_keys` (CONTRACTS 12.5) are callable
through `auth.api.call(...)` only, never over HTTP. `verify_api_key` runs every
plugin's principal checks, as a request would (CCR 015): a key of a banned user (P6)
answers `valid: false` with `ADMIN_USER_BANNED`.
