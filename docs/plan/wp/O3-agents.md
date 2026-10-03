# O3: Agent identities v1

| | |
|---|---|
| Lane / wave | Agent and OAuth / **Wave 3** |
| Size | M |
| Depends on | P1, O1; P5 for org-owned agents |
| Can start | after P1 merges, with stubs of O1's server_only endpoints; client linking after O1 |
| Write scope | `src/gotauth/plugins/agent/**` (except `delegation/`, O4), `tests/plugins/agent/**`, `changes/O3.*.md` |
| Allowed new deps | none |

## Goal
AI agents get their own identity, owned by a user or an organization, with their own API keys and OAuth clients. Every request records which agent acted for whom, and one call revokes everything an agent holds.

## Build
- `agent()`, id `"agent"`, `from gotauth.plugins.agent import agent`. Requires `api_key` (`ConfigError` otherwise). Without `oauth_provider`, `link_oauth_client` is not registered.
- Model `agent` exactly as 12.2 (`created_by` -> user, set_null), ids `agt_...`.
- Endpoints (ids, paths and auth exactly as 12.3; all `session`, tag `agents`):

  | id | Method + path |
  |---|---|
  | `create_agent` | POST `/agents` |
  | `list_agents` | GET `/agents` |
  | `get_agent` | GET `/agents/{id}` |
  | `update_agent` | PATCH `/agents/{id}` |
  | `revoke_agent` | POST `/agents/{id}/revoke` (fresh) |
  | `create_agent_api_key` | POST `/agents/{id}/api-keys` |
  | `list_agent_api_keys` | GET `/agents/{id}/api-keys` |
  | `link_oauth_client` | POST `/agents/{id}/clients` |

- Ownership: `create_agent` `{name, description?, organization_id?, metadata?}`. With `organization_id`, the org owns it and the caller needs P5 `has_permission` `{"agent": ["create"]}` (a P5 built-in statement, 12.3; no P5 -> `FORBIDDEN`); else the session user. `created_by` = session user. Afterwards: user-owned -> owner only; org-owned -> `agent: [read|update|revoke]`. Anyone else -> `NOT_FOUND`.
- `update_agent`: `name?`, `description?`, `metadata?`, `enabled?`. `enabled=true` clears `disabled_at` (owner only); keys and tokens revoked earlier stay revoked.
- `revoke_agent`, one transaction, idempotent: set `disabled_at`; P1 `revoke_api_keys(owner_type="agent", owner_id=id)`; O1 `update_oauth_client(disabled=True)` for linked clients and `revoke_oauth_tokens(agent_id=id)`. Emits `agent.revoked` with counts.
- `create_agent_api_key` `{name, scopes, expires_in?}`: agent must be enabled (else `AGENT_DISABLED`); calls P1 `issue_api_key` with `owner_type="agent"`, `owner_id` = agent id, `user_id` = owning user (user-owned) or None (org-owned), `created_by` = session user. Raw key returned once. `list_agent_api_keys` lists that agent's keys (never hashes).
- `link_oauth_client` `{client_id}`: the client's `owner_user_id` must be the agent's owning user (org: caller has `agent: [update]`) and it must not be linked elsewhere (`AGENT_CLIENT_ALREADY_LINKED`); sets `agent_id` via `update_oauth_client`. O1 then adds `act: {"sub": agent id}` to its tokens. Deleting the agent sets `oauth_client.agent_id` to null (12.2).
- Principal: P1 sets `agent_id` for agent keys, O1 from `act`; `user_id` is the owning user or None, never the agent id (12.1). O3 adds no resolver. Calls into P1/O1 go through `auth.api.call(...)` only.
- User deletion (`delete_user`, 13): a user `before_delete` hook in `Plugin.database_hooks` runs the `revoke_agent` steps for that user's agents and deletes them (polymorphic owner, no FK).
- Error codes: `AGENT_DISABLED` 403, `AGENT_CLIENT_ALREADY_LINKED` 409. Events: `agent.created`, `agent.revoked` (ids and owner, never secrets).
- Server-only `revoke_agents` `{owner_type, owner_id}` -> `{revoked}` (CONTRACTS 12.3, 12.5) runs the `revoke_agent` steps for every agent of that owner. P5 calls it on organization deletion, and O3's own user `before_delete` hook uses it.
- Calls to P1 and O1 go through `ctx.auth.api.call(..., ctx=ctx)` with the 12.5 shapes, so they share one transaction. Tests use `stub_plugin("api_key", ...)` and `stub_plugin("oauth_provider", ...)` to assert on the exact inputs.

## Acceptance tests
- After `revoke_agent`, no clock advance: agent key -> 401; refresh token -> `invalid_grant`; access token -> 401 (resolver and `verify_access_token`); a new authorize for the linked client fails.
- A linked client's access token has `act.sub` = agent id; its `Principal` has `agent_id` and `user_id`. An agent key's principal has `agent_id` plus `user_id` (user-owned) or `organization_id` (org-owned). A `client_credentials` token of an org-owned agent has `user_id=None`.
- Non-owners cannot get, update, re-enable, revoke or mint keys (404). The owner can re-enable; old keys stay dead.
- Org-owned: member without the `agent` permission -> 403; with it -> ok.
- Linking another user's client -> 404; an already linked client -> 409.
- `delete_user` on an owner: their agents are gone and every agent credential gets 401.
- An event emitted by an endpoint called with an agent key carries `principal.agent_id` and `principal.user_id` (14).
- Hypothesis: for any sequence of mint key / link client / revoke / re-enable, no credential issued before the last revoke resolves afterwards.

## Out of scope
Delegation (O4), agent UI (D2), MCP helpers (O2), org roles (P5).

## Notes
- P1 checks validity on every request with no cache; O1 may cache for up to 5s (12.2) but clears the cache on its own revocations, so revocation is immediate in-process and the tests need no clock advance.
