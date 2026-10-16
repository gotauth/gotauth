# CCR: principal checks outside the request pipeline

- Requested by: Q1 (security tests for the plugins)
- Status: accepted 2026-10-16 (CONTRACT_VERSION 15)
- CONTRACTS sections: 13 (`GotAuthInstance`)
- Affected work packages: C1 (implements), F2 (testing kit), O1 (verifies and mints access tokens), P1 (`verify_api_key`), P6 (its ban check now reaches these paths)

## Change
`GotAuthInstance.check_principal(ctx: EndpointContext, principal: Principal) -> None` runs every plugin's `principal_checks` on `principal`, the same checks the pipeline runs after it resolves a credential. It raises `AuthError` when a check refuses.

Callers:
- O1 checks the principal of a token in `verify` (used by `verify_access_token`, introspection and userinfo) and in `_mint` (the authorization code, refresh token and client credentials grants), and the owner of a refresh token in introspection. A token that acts for no user or agent (client credentials) is also checked as its client's `owner_user_id`. `verify_access_token` answers `valid: false` with the check's error code, introspection `active: false`, userinfo 401 and a grant `invalid_grant`. Its resource-server resolver skips the check, because the pipeline runs it next and answers with the check's own error.
- P1's `verify_api_key` answers `valid: false` with the check's error code.
- A check that fails (`INTERNAL_ERROR`, 500) is raised, never turned into a refusal, so a database error does not make clients drop valid refresh tokens.

## Why
The pipeline runs principal checks only for credentials presented to GotAuth's own endpoints. The server calls that other code uses to accept credentials did not, so after P6 banned a user:
- `verify_access_token` still answered `valid: true`. MCP servers in the same process verify tokens this way, so the user's MCP tools kept working.
- introspection still answered `active: true`, so MCP servers that introspect accepted the token too
- the refresh grant still issued new tokens, so the access never ended
- `verify_api_key` still accepted the user's keys

## Compatibility
Additive for callers. A custom `GotAuthInstance` (none outside the testing kit) needs the method. A principal check now also runs for these paths, so a check must not assume a request with a session.

## Blocked work
Q1's ban test.
