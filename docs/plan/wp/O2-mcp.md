# O2: MCP integration (FastMCP + MCP SDK) + MCP example

| | |
|---|---|
| Lane / wave | Agent and OAuth / **Wave 3** (never cut) |
| Size | M |
| Depends on | O1 |
| Can start | after O1's token issuance merges; earlier against JWTs minted in tests with test keys |
| Write scope | `src/gotauth/integrations/mcp/**`, `tests/integrations/mcp/**`, `examples/fastmcp-server/**`, `changes/O2.*.md` |
| Allowed new deps | runtime: `mcp`, `fastmcp` (existing `mcp` extra, lazy import); example-only: fastapi, uvicorn |

## Goal
Protect a Python MCP server with GotAuth in a few lines: verify GotAuth access tokens, advertise GotAuth as the authorization server (RFC 9728) and give tools the user, agent and scopes (12.4). Ship the MCP demo app.

## Build
- `fastmcp_auth(auth=None, *, issuer=None, resource, scopes=(), introspect=False, introspection_client=None)`: a FastMCP auth provider on FastMCP's remote-provider pattern (token verifier + authorization servers; it serves the RFC 9728 metadata). Exactly one of `auth`/`issuer`, else `ConfigError`.
- `mcp_sdk_auth(...)`, same parameters -> `(AuthSettings, TokenVerifier)`: `issuer_url`, `resource_server_url=resource`, `required_scopes=scopes`.
- `protected_resource_metadata(*, resource, issuer, scopes)` -> `{resource, authorization_servers: [issuer], scopes_supported, bearer_methods_supported: ["header"]}`; `scopes_supported` never contains `offline_access` (12.4).
- Verification:
  - Same-process (`auth=`): `auth.api.call("verify_access_token", ...)` (O1 server_only), no HTTP. Checks signature, `typ at+jwt`, `iss`, `exp`, `aud` contains `resource`, revocation, disabled clients and agents, so revoke -> 401 on the next call (12.2). `introspect` is ignored here.
  - Remote (`issuer=`): discovery; JWKS cached, refetched on an unknown `kid` at most once per 30s; algorithm pinned per key (never `none` or HS*); same claim checks. Without `introspect`, a revoked token works until it expires (default 10m, 12.2); document it. `introspect=True` adds RFC 7662 introspection at the issuer's `introspection_endpoint` (short cache) for immediate revocation.
  - Missing scope -> 403, `WWW-Authenticate: Bearer error="insufficient_scope", scope="<all scopes the call needs>", resource_metadata="<url>"`.
  - Missing token -> 401, `WWW-Authenticate: Bearer resource_metadata="<url>", scope="<configured scopes>"` (`scope` omitted when none are configured).
  - Bad or expired token -> the same, plus `error="invalid_token"`, which comes first: `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="<url>", scope="<configured scopes>"`.
  - `<configured scopes>` is the `scopes` argument, space-separated, without `offline_access`. GotAuth builds or checks these headers itself and does not assume the framework does: FastMCP ([#4513](https://github.com/PrefectHQ/fastmcp/issues/4513)) and the MCP SDK ([#3103](https://github.com/modelcontextprotocol/python-sdk/issues/3103)) both shipped them wrong.
- `GotAuthAccess` (`user_id`, `agent_id` from `act.sub`, `client_id`, `scopes`, `jti`), exposed through each framework's access-token accessor and a `current_access()` helper. `user_id` follows 12.1, never an agent or client id: same-process, from the returned `Principal`; remote, `sub` unless the token is a `client_credentials` token (`sub` equals `client_id` or `act.sub`), then None.
- `examples/fastmcp-server/`:
  - FastAPI app hosting GotAuth: email + password and passkey login (P3; password only until P3 merges), `oauth_provider(mcp=True, resources=[<MCP URL>])`, consent page, `auth.well_known()` mounted at `/` (or A1's `well_known_router()`), a "Connected apps" page with Revoke (`revoke_oauth_tokens`).
  - FastMCP server in the same process: `fastmcp_auth(auth, resource=..., scopes=[...])`; tools `list_projects` (`projects:read`), `create_project` (`projects:write`).
  - Seeds a static public client via `create_oauth_client` (loopback redirect) for MCP Inspector and Q2, since CIMD rejects loopback hosts.
  - `compose.yaml`, `.env.example`, `README.md` with the MCP clip script: Claude adds the server as a custom connector -> passkey login + consent -> tools work -> revoke in the app -> next call 401. Plus MCP Inspector steps.
- `verify_access_token` is called with the CONTRACTS 12.5 shape `{token, resource, scopes}` and returns `{valid, code?, principal?}`. Before O1 merges, tests use `stub_plugin("oauth_provider", {"verify_access_token": ...})`.

## Acceptance tests
- In-memory FastMCP client and MCP SDK client with tokens from O1's flow (or test-minted): `list_projects` works; `create_project` without `projects:write` -> 403 with the header above.
- Wrong `aud`, expired, bad signature, `alg: none`, unknown `kid` -> 401 with `error="invalid_token"` and `resource_metadata`.
- The 401 and 403 headers match the lines above, byte for byte, for FastMCP and the MCP SDK.
- `protected_resource_metadata(scopes=["projects:read", "offline_access"])` lists only `projects:read`.
- Same-process: `revoke_oauth_tokens` -> next call 401, no clock advance.
- Remote with mocked JWKS: a rotated key is used after one refetch; a flood of unknown `kid`s stays within the refetch limit; with `introspect=True` and a mocked introspection response `active=false` -> 401 at once.
- RFC 9728 document served at the path form for a resource with a path (`/.well-known/oauth-protected-resource/mcp`), listing the issuer.
- A tool sees `agent_id` for an agent-linked client's token (test-minted until O3 merges); a `client_credentials` token never shows the agent or client id as `user_id`.
- Example: an automated test runs login, consent, tool call, revoke, 401 with httpx and an in-memory client.

## Out of scope
The authorization server (O1), agents (O3), the FastMCP docs PR (owner), launch posts (G5).

## Notes
- `introspect=True` authenticates to O1's introspection endpoint as the confidential client given in `introspection_client=(client_id, client_secret)` (CONTRACTS 12.4); `introspect=True` with `issuer=` and no `introspection_client` raises `ConfigError`. `mcp_sdk_auth` takes the same parameters.
- FastMCP and MCP SDK auth APIs change often. The plan assumes FastMCP 4.x and `mcp` 2.x as of 2026-10 (R1 found `fastmcp` 4.0.10 of 2026-09-25 and `mcp` 2.3.0 of 2026-10-02 on PyPI): check current docs and source, record exact versions in the README, and list differences in the PR.
- Read the MCP authorization spec revision O1 targets (2026-07-28) for the RFC 9728 and `WWW-Authenticate` rules.
- Revision 2026-07-28 makes the protocol stateless: it removes `initialize` and `Mcp-Session-Id`. The in-memory client tests use the stateless request form those FastMCP and `mcp` versions expose.
- Enterprise-managed authorization (SEP-990, the identity assertion grant) is an extension, not core MCP. It is not part of v0.1; it is a candidate for O4 or later.
- Claude custom connectors need a public https URL: document a tunnel, with `base_url` set to the tunnel URL (`oauth_provider(mcp=True)` accepts only an `https` or loopback `base_url`). MCP Inspector works on localhost.
