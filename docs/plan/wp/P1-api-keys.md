# P1: API keys

| | |
|---|---|
| Lane / wave | Plugins / **Wave 1, late** (week 3, against the testing kit; critical path to M2) |
| Size | M |
| Depends on | M0 (testing kit); C1 for HTTP tests |
| Can start | after M0 against `gotauth.testing`; HTTP tests after C1 |
| Write scope | `src/gotauth/plugins/api_key/**`, `tests/plugins/api_key/**`, `changes/P1.*.md` |
| Allowed new deps | none |

## Goal
Scoped, revocable API keys for users, organizations and agents, resolved into a `Principal` (12.1) by the `gak_` prefix. Hashed at rest, shown once.

## Build
- `api_key(*, allowed_scopes=(), default_expires_in=None, max_expires_in=None, rate_limit=None)`, id `"api_key"`, imported as `from gotauth.plugins.api_key import api_key` (13.2). Keys carry only `allowed_scopes` (empty = none). `rate_limit` = default per-key `(max, window)`.
- Model `api_key` exactly as 12.2, ids `key_...`. Key = `crypto.random_token("gak_")` (7); only `hash_token(key)` stored; `start` = 6 chars after the prefix.
- Endpoints (ids and paths as 12.3, tag `api-keys`):
  - `create_api_key` POST `/api-keys`, session. In: `name`, `scopes`, `expires_in?`, `organization_id?`, `metadata?`, `rate_limit_max?`, `rate_limit_window?`. Out `{api_key: ApiKeyOut, key}`: the only time the raw key appears. User key: `owner_type="user"`, `owner_id` = `user_id` = session user. Org key (`organization_id`): `owner_type="organization"`, `user_id=None`; needs P5 `has_permission` `{"api_key": ["create"]}` (list `read`, update `update`, delete `revoke`; no P5 -> `FORBIDDEN`). `created_by` = session user. Never `owner_type="agent"`.
  - `list_api_keys` GET `/api-keys`, session (`organization_id?` query).
  - `update_api_key` PATCH `/api-keys/{id}`, session: `name?`, `scopes?`, `enabled?`, `expires_at?`.
  - `delete_api_key` DELETE `/api-keys/{id}`, session; removes the row. Keys you don't own -> `NOT_FOUND`.
  - server_only: `verify_api_key` POST `/api-keys/verify` (`{key, scopes?}` -> `{valid, code?, principal?}`); `issue_api_key` POST `/api-keys/issue` (any owner, explicit `user_id` and `created_by`, no session checks; used by O3); `revoke_api_keys` POST `/api-keys/revoke` (`{owner_type, owner_id, key_id?}`, disables).
- `ApiKeyOut`: `returned=True` fields only. Scopes outside `allowed_scopes` -> `INVALID_REQUEST`.
- `PrincipalResolver`, `prefixes=("gak_",)`, `Authorization: Bearer` or `x-api-key`:
  - Lookup by hash, confirm with `crypto.equal`. Errors: `API_KEY_INVALID` 401, `API_KEY_DISABLED` 401, `API_KEY_EXPIRED` 401, `API_KEY_RATE_LIMITED` 429 + `Retry-After`.
  - Principal: `via="api_key"`, `credential_id` = key id, `scopes=frozenset(key.scopes)` (never `None`, so never session rights), `user_id=key.user_id` (never an agent id), `organization_id` for org keys. Agent keys: `agent_id=owner_id`, `organization_id` of an org-owned agent; rejected if the agent is disabled.
  - Banned users: P6's `PrincipalCheck` (5) rejects their keys after resolution; P1 adds no ban check.
  - `last_used_at`: compare-and-set, at most once per minute per key.
  - Per-key limits: `secondary_storage.incr` if configured, else in-process window (document the multi-process caveat).
  - No validity cache: revocation and expiry apply on the next request.
- Events: `api_key.created`, `api_key.revoked` on delete or disable (data: id, `start`, owner; never the key).
- User deletion goes through `ctx.auth.delete_user` (13); the FK cascade on `api_key.user_id` removes the user's keys and their user-owned agents' keys. No hook needed.
- `issue_api_key`, `revoke_api_keys` and `verify_api_key` take and return exactly the CONTRACTS 12.5 shapes. O3 and P5 call them through `auth.api.call(..., ctx=ctx)` and test against `stub_plugin`, so any change needs a CCR.

## Acceptance tests
- After create, a dump of every row (memory and SQLite) never contains the raw key; list/update never return it.
- Right after delete, `enabled=False` or `expires_at` (fake clock) the key gets 401 with the matching code.
- Bearer and `x-api-key` work; a random `gak_` value -> `API_KEY_INVALID`; a key cannot call session endpoints.
- Endpoint with `auth="principal"`, `scopes=("projects:read",)`: key without it -> 403 `INSUFFICIENT_SCOPE`; with it -> 200.
- Other users' key ids -> 404; org key without P5 -> 403; scope outside `allowed_scopes` -> 400.
- Org key principal: `user_id is None`, `organization_id` set, `created_by` = creator.
- `delete_user` removes the user's keys (SQLite FK cascade and memory adapter).
- Hash comparison uses `crypto.equal` (spy).
- 10 requests in a minute write `last_used_at` once; again after `advance("61s")`.
- `max + 1` requests -> 429 + `Retry-After`.
- Hypothesis: keys match `^gak_[A-Za-z0-9_-]{43}$`, `start == key[4:10]`, `hash_token(key) == key_hash`, resolve to their own id; other prefixed strings never resolve.
- No event contains a key.

## Out of scope
Agent keys (O3), org permissions (P5), ban checks (P6), key UI (D2), FastAPI dependencies (A1).

## Notes
Display keys as `gak_<start>...`. O3 calls `issue_api_key` and `revoke_api_keys`: keep their inputs stable.
