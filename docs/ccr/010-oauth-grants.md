# CCR: users list and revoke the apps they authorized

- Requested by: Q1 ([request](../requests/Q1-O1-asvs-gaps.md), item 1; issue #7)
- Status: accepted 2026-10-13 (CONTRACT_VERSION 10)
- CONTRACTS sections: 12.3 (endpoint table)
- Affected work packages: O1 (implements), D2 (a "Connected apps" component can follow), O2 (the example's "Connected apps" page)

## Change
Two session endpoints in O1:

| id | Route | Output |
|---|---|---|
| `list_oauth_grants` | GET `/oauth2/grants` | `{grants: [{client_id, client_name, scopes, resources, created_at, last_used_at}]}` |
| `revoke_oauth_grant` | POST `/oauth2/grants/revoke` `{client_id}` | `{revoked: int}` |

- A grant is one client that has a stored consent or live (not revoked, not expired) tokens for the signed-in user.
  - `scopes` and `resources` merge its consents and tokens.
  - `created_at` is the earliest of them.
  - `last_used_at` is when the client last got tokens (sign-in or refresh), or `null`.
- Revoking a grant does three things for that client and user:
  - deletes the consent and any unused authorization codes
  - revokes every token: access tokens check their row, so they stop working at once
  - emits `oauth.token_revoked` when tokens were revoked

  Revoking a client the user has no grant for returns `{revoked: 0}`, so it says nothing about other users.

## Why
ASVS 10.7.3 (users can review and revoke what they authorized) and 10.4.9 (users can revoke tokens) are Level 2. Before this, consents and tokens were server-only: a user could not see which apps, including agents connected through MCP, held access, or cut one off.

## Compatibility
Additive. Apps that mount the plugin get two new session routes.

## Blocked work
None.
