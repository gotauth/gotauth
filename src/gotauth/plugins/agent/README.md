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
Linking OAuth clients needs `oauth_provider()`; without it, `POST /agents/{id}/clients`
answers 404.

## Endpoints (session)

| Endpoint | What |
|---|---|
| `POST /agents` | `{name, description?, organization_id?, metadata?}`. Owned by the session user, or by the organization: then the caller needs P5's `agent: [create]` |
| `GET /agents` | Your agents, or `?organization_id=` (needs `agent: [read]`) |
| `GET /agents/{id}` | One agent |
| `PATCH /agents/{id}` | `name`, `description`, `metadata`, `enabled`. `enabled: false` revokes like the next row; `enabled: true` re-enables, and what was revoked stays revoked |
| `POST /agents/{id}/revoke` | Fresh session. Disables the agent, revokes its API keys, disables its linked OAuth clients and revokes their tokens, in one transaction. Idempotent. Returns the counts |
| `POST /agents/{id}/api-keys` | `{name, scopes, expires_in?}`: a key owned by the agent, shown once. `AGENT_DISABLED` (403) for a disabled agent |
| `GET /agents/{id}/api-keys` | The agent's keys, never the hashes |
| `POST /agents/{id}/clients` | `{client_id}`: link one of your OAuth clients. Its tokens then carry `act: {"sub": "<agent id>"}`. Another user's client is a 404; a client linked to another agent is `AGENT_CLIENT_ALREADY_LINKED` (409) |

**Ownership.**
- A user's agent is visible only to that user. Anyone else gets 404.
- An organization's agent needs P5's `agent` permission for the action. Without P5 installed, organization agents are refused (403).

**Server only.** `revoke_agents` `{owner_type, owner_id}` runs the revoke steps for
every agent of an owner. P5 calls it when an organization is deleted.

## Principals

- **An agent's API key:** the `Principal` has `agent_id`, plus `user_id` for a user's agent or `organization_id` for an organization's.
- **A linked client's token:** `agent_id` comes from the `act` claim.
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
