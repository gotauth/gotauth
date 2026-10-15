# CCR: consent details for an app's own consent page

- Requested by: D2 (code review of the registry's ConsentScreen)
- Status: accepted 2026-10-15 (CONTRACT_VERSION 14)
- CONTRACTS sections: 12.3 (endpoint table)
- Affected work packages: O1 (implements), D2 (`client.oauth2.getOauthConsent`, ConsentScreen), G4 and O2 (consent pages)

## Change
One session endpoint in O1:

| id | Route | Output |
|---|---|---|
| `get_oauth_consent` | GET `/oauth2/consent?consent_id=...` | `{consent_id, client: {client_id, name, host}, scopes, resource, redirect_host, loopback_only}` |

- It reads the signed consent request that `oauth_authorize` made. A forged, expired or other user's `consent_id` gets `TOKEN_INVALID` (400), as `oauth_consent` does.
- The output has the same shape as `oauth_authorize` in JSON mode.

## Why
With `consent_page` set, `oauth_authorize` sends the browser to `consent_page?consent_id=...`, and nothing else. The page had no way to show the app's name, the redirect host (which MCP authorization 2026-07-28 requires on screen) or the scopes. Calling `oauth_authorize` again from the page in JSON mode does not work either: the page no longer has the authorization query. When consent is already stored, that call issues a code the page cannot use.

## Compatibility
Additive. `POST /oauth2/consent` is unchanged.

## Blocked work
D2 part 2's ConsentScreen.
