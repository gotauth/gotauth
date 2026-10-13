# Q1: OAuth server gaps from the ASVS mapping and the conformance setup

| | |
|---|---|
| From | Q1 (`docs/security/asvs.md`, `docs/security/conformance/`) |
| For | O1 (`src/gotauth/plugins/oauth_provider/`); item 1 adds endpoints, so it needs a CCR (CONTRACTS 12.3 table) |
| Date | 2026-10-10 |
| Status | Applied 2026-10-13 (issue #7): item 1 as [CCR 010](../ccr/010-oauth-grants.md), item 2 in the conformance app and `plan.json` |

## What and why

### 1. Users cannot see or revoke their grants (ASVS 10.7.3 and 10.4.9, Level 2)
Consents are stored, and `revoke_oauth_tokens` revokes by user or client. But both are server-only, so a user has no way to see which apps hold access or to cut one off. This matters most for agents connected through MCP.

**Proposed:**
- `list_oauth_grants` at `GET /oauth2/grants` (session): the user's consents, each with the client name, scopes, resource, `created_at` and last use.
- `revoke_oauth_grant` at `POST /oauth2/grants/revoke` (session, `{client_id}`): deletes the consent and revokes that client's tokens for the user.
- A registry component, `ConnectedApps`, can follow in D2 part 2.

### 2. The conformance app has no sign-in page
`conformance:create_app` sends unauthenticated `/oauth2/authorize` requests to `login_page="/sign-in"`, but serves nothing there. The OpenID conformance suite's browser steps need a page to fill in.

**Proposed:** a minimal HTML form at `/sign-in` in the conformance app. It signs in a fixed test user created at startup, then follows `callback_url`. Add the matching `browser` block (sign-in form, then the consent "Allow" button) to `plan.json`.

## In the meantime
`docs/security/asvs.md` records 10.7.3 as not met and 10.4.9 as partial. The conformance result file records the run as blocked on item 2 and on a public URL.
