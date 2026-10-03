# O4: Delegation chains (RFC 8693)

| | |
|---|---|
| Lane / wave | Agent and OAuth / **Wave 4** (gated) |
| Size | L |
| Depends on | O3, O1 |
| Can start | only after M3, a passed post-launch test, and public requests for delegation |
| Write scope | `src/gotauth/plugins/agent/delegation/**`, `tests/plugins/agent/delegation/**`, `changes/O4.*.md` |
| Allowed new deps | none |

## Goal
Let an agent act for a user, and an agent for another agent, with tokens that only narrow, carry the whole chain and die with their parent.

## Build
- Grant `urn:ietf:params:oauth:grant-type:token-exchange` on `oauth_token` (POST `/oauth2/token`, form input, RFC 6749 errors through `error_format="oauth"`), registered in O1's grant registry; off by default (`delegation=True` on the agent plugin).
- `subject_token`: the user's GotAuth access token (or an exchanged token, for chains). `actor_token`: an agent credential (agent API key or an agent client's `client_credentials` token). The requesting client must be linked to the actor agent (O3).
- Requested scopes must be a subset of the subject token's scopes; `resource` must be in O1's `resources`. Never widened.
- Nested `act`: current actor outermost, prior actors nested inside (RFC 8693 section 4.1). `max_delegation_depth` (default 3); deeper -> `invalid_grant`.
- Exchanged tokens live no longer than the subject token; no refresh token (`refresh_token_hash` stays null, 12.2). `user_id` = the subject token's user; `agent_id` = the current actor.
- Family tracking: each exchanged token sets `oauth_token.parent_id` (12.2) to its parent; revoking a parent (token, family, consent or agent) revokes every descendant. Revocation follows 12.2: immediate for in-process checks, at expiry for remote JWT-only resource servers.
- Events: `oauth.token_revoked` for each cascade, data includes the chain of agent ids.

## Acceptance tests
- Hypothesis over random chains: every child's scopes are a subset of its parent's, depth <= max, and `act` nesting matches the chain order.
- Revoking the root revokes all descendants; revoking a child leaves its parent working.
- A disabled agent anywhere in the chain -> exchange refused and its descendants 401.
- Widened scope, foreign `resource`, client not linked to the actor, depth max + 1 -> rejected with RFC 6749 errors.

## Out of scope
Agent identities (O3), the core grants (O1), policy engines.

## Notes
- Gated: start only with public evidence (issues, discussions, inbound integration requests) that users need delegation. Keep the design light until then.
- Check RFC 8693 and the then-current MCP authorization spec for delegation guidance; record versions.
