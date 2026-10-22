# gotauth.plugins.agent

Agent identities (work package O3, CONTRACTS 12.2 and 12.3). An AI agent gets its own
identity, owned by a user or an organization, with its own API keys and OAuth
clients:
- every request records which agent acted for whom
- one call revokes everything the agent holds

```python
from gotauth.plugins.agent import agent
from gotauth.plugins.api_key import api_key
from gotauth.plugins.oauth_provider import oauth_provider

auth = GotAuth(..., plugins=[api_key(), oauth_provider(), agent()])
```

`agent()` needs `api_key()` (a `ConfigError` before the first request otherwise).
Linking OAuth clients needs `oauth_provider()`. Without it, `POST /agents/{id}/clients`
answers 404. The route still exists, because a plugin's endpoints are fixed when it is
built, before it knows the other plugins.

## Endpoints (session)

| Endpoint | What |
|---|---|
| `POST /agents` | `{name, description?, organization_id?, metadata?}`. Owned by the session user, or by the organization: then the caller needs P5's `agent: [create]` |
| `GET /agents` | Your agents, or `?organization_id=` (needs `agent: [read]`) |
| `GET /agents/{id}` | One agent |
| `PATCH /agents/{id}` | `name`, `description`, `metadata`, `enabled: true`. Re-enabling needs the revoke right; it first revokes anything created while the agent was being revoked, and what was revoked stays revoked. `enabled: false` is a 400: disable with the next row, which needs a fresh session |
| `POST /agents/{id}/revoke` | Fresh session. Disables the agent, revokes its API keys, disables its linked OAuth clients and revokes every token of those clients (also tokens from before the link), in one transaction. Idempotent. Returns the counts |
| `POST /agents/{id}/api-keys` | `{name, scopes, expires_in?}`: a key owned by the agent, shown once. `AGENT_DISABLED` (403) for a disabled agent. For an organization's agent the key acts for the organization, so the caller also needs P1's `api_key: [create]` |
| `GET /agents/{id}/api-keys` | The agent's keys, never the hashes |
| `POST /agents/{id}/clients` | `{client_id}`: link one of your OAuth clients. Its tokens then carry `act: {"sub": "<agent id>"}`. Another user's client is a 404; a client linked to another agent is `AGENT_CLIENT_ALREADY_LINKED` (409); a disabled client (for example after a revoke) is `AGENT_CLIENT_DISABLED` (409): enabling it again is the app's call (`update_oauth_client`) |

**Ownership.**
- A user's agent is visible only to that user.
- An organization's agent needs P5's `agent` permission for the action.
- Anyone else gets 404, so an agent id says nothing to someone who may not use it.
- Creating or listing an organization's agents without the permission is a 403, and so is any organization agent when P5 is not installed.

**Server only.** `revoke_agents` `{owner_type, owner_id}` runs the revoke steps for
every agent of an owner. P5 calls it when an organization is deleted.

Calls into P1 and O1 go through `auth.api.call(...)` in the caller's transaction.
The one exception is listing an agent's keys: P1 has no listing call, so O3 reads the
`api_key` table through the shared schema, as P1 reads `agent`.

## Principals

- **An agent's API key:** the `Principal` has `agent_id`, plus `user_id` for a user's agent or `organization_id` for an organization's.
- **A linked client's token:** `agent_id` comes from the `act` claim. For an organization's agent it carries no `organization_id`: the agent acts for the organization through its API keys, which have the organization's limits (issue #42).
- **The client's owner** holds its secret, so the principal checks (a ban) also run on them for every token of the client that acts for no user. Leaving or being removed from the organization does not unlink their client; revoke the agent or disable the client for that.
- **A `client_credentials` token of a user's agent:** acts for that user.
- **Never the agent:** `user_id` is never the agent id.

## Deleting a user

A user `before_delete` hook revokes everything that user's agents hold and deletes
them, in the delete's transaction (CCR 011).

## Events

`agent.created` and `agent.revoked`, with the agent id, owner and revoked counts.
They never include keys or tokens.

## Tests

`tests/plugins/agent/`:
- ownership and not-found rules
- keys, client linking and the `act` claim
- revocation with no clock advance, re-enabling and owner deletion
- events
- a Hypothesis test: for any sequence of minting keys, linking clients, revoking and re-enabling, nothing issued before the last revoke still works

Organization agents need P5 and are tested when it merges.
