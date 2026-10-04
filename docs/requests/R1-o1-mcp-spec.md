# R1 request: align O1, O2 and CONTRACTS 12.1-12.4 with MCP authorization 2026-07-28

| | |
|---|---|
| From | R1 (validation addendum) |
| For | the integrator; affects CONTRACTS 12.1, 12.3 and 12.4, and the O1 and O2 briefs |
| Date | 2026-10-04 (spec read on 2026-10-03) |
| Before M0? | Yes. Request only; after M0 this becomes a CCR |
| Changes a 12.5 cross-plugin shape? | No |

## What was checked
- **The spec revision.** MCP authorization revision **2026-07-28** exists and is the latest (`/specification/latest` redirects to it).
  - Text read at commit [db4bfcf](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/db4bfcff3d60f5df01a21bdf6b78f7012cac4634/docs/specification/2026-07-28/basic/authorization).
  - Pages: [overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [authorization server discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery), [client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration), [security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations).
- **The drafts it cites.**
  - CIMD [draft-ietf-oauth-client-id-metadata-document-00](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00); the current revision is [-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02) (2026-07-06).
  - OAuth 2.1 draft-13; the current revision is draft-16.
- **The full requirement table and comparison** are in [validation-research.md, section 2 of the MCP auth addendum](../research/validation-research.md#2-mcp-authorization-spec-revision-2026-07-28).

**What already matches** (no change needed):
- PKCE S256 only
- CIMD on by default
- DCR off by default (the spec now deprecates DCR)
- RFC 8414 path insertion at the host root plus OIDC discovery inside the mount
- refresh token rotation with family revocation
- 10-minute access tokens
- RFC 9068 tokens with `aud` = resource
- the revocation semantics in 12.2

The items below are the differences. Each one gives the target, the reason, and the exact text to change.

## 1. Name the discovery metadata fields
**Target:** O1 brief, "Discovery" bullet; CONTRACTS 12.3, `oauth_server_metadata` row.

**Why:**
- AS metadata advertises CIMD with `client_id_metadata_document_supported` ([advertising CIMD support](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#advertising-cimd-support)).
- Clients refuse to continue without `code_challenge_methods_supported`, and an AS offering OIDC discovery MUST include it ([authorization code protection](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#authorization-code-protection)).
- An AS that sends `iss` MUST set `authorization_response_iss_parameter_supported` ([authorization response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation)).
- Clients pick DCR only when `registration_endpoint` is present ([client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)).

**Change (O1 brief):**
```diff
-  - Discovery: `oauth_openid_configuration` inside the mount; `oauth_server_metadata` in `Plugin.well_known_endpoints`, at the host root via `auth.well_known()` (RFC 8414 path insertion). Same metadata, incl. `code_challenge_methods_supported: ["S256"]` and CIMD support.
+  - Discovery: `oauth_openid_configuration` inside the mount; `oauth_server_metadata` in `Plugin.well_known_endpoints`, at the host root via `auth.well_known()` (RFC 8414 path insertion). Both serve the same document with at least: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`, `scopes_supported`, `response_types_supported: ["code"]`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported: ["S256"]`, `authorization_response_iss_parameter_supported: true`, and `client_id_metadata_document_supported: true` when `allow_cimd`. `registration_endpoint` appears only when `allow_dynamic_registration`.
```
**Acceptance test to add (O1):** both documents contain exactly these keys. `registration_endpoint` is absent by default and present when DCR is on.

## 2. Send `iss` on every redirect back to the client
**Target:** O1 brief, "Authorize" bullet.

**Why:** RFC 9207 `iss` SHOULD be in authorization responses, error responses included. A future MCP revision is expected to make it a MUST ([authorization response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation)).

**Change:**
```diff
-  ... `state`, `nonce`, `prompt`; `iss` in the response (RFC 9207); ...
+  ... `state`, `nonce`, `prompt`; `iss` on every redirect to the client, success and error alike (RFC 9207 section 2), equal to the metadata `issuer`; ...
```
**Acceptance test to add (O1):** a denied consent and an `invalid_scope` redirect both carry `iss`.

## 3. Pin down which redirect URIs are allowed
**Target:** CONTRACTS 12.3, "OAuth server rules", the redirect bullet; O1 brief, "Authorize" bullet.

**Why:**
- "All redirect URIs **MUST** be either `localhost` or use HTTPS" ([communication security](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#communication-security)), with exact matching ([open redirection](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#open-redirection)).
- The CIMD example document lists both `http://127.0.0.1:3000/callback` and `http://localhost:3000/callback` ([example](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#example-metadata-document)).
- DCR clients MUST send `application_type` ([application type](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#application-type-and-redirect-uri-constraints)).
- Real bugs in this area: FastMCP [#3598](https://github.com/PrefectHQ/fastmcp/issues/3598) and [#3574](https://github.com/PrefectHQ/fastmcp/issues/3574).

**Change (CONTRACTS 12.3):**
```diff
-- **Exact `redirect_uri` match.** Loopback redirect URIs may use any port (RFC 8252).
+- **Redirect URIs.** A registered or presented `redirect_uri` must be `https`, or `http` with a loopback host (`localhost`, `127.0.0.1` or `[::1]`). No fragment, no userinfo, no custom schemes in v0.1. Matching is an exact string comparison, except that for a loopback host the port may differ (RFC 8252 section 7.3). The rule applies at `create_oauth_client`, at CIMD load and at DCR. With DCR on, `application_type` is required: `native` allows only loopback redirects, `web` only `https`.
```
**Acceptance tests (O1):**
- `http://example.com/cb` is rejected at client creation.
- `http://localhost:5555/cb` matches a registered `http://localhost:3000/cb`.
- `http://127.0.0.1.nip.io/cb` is not treated as loopback.

## 4. Tighten CIMD validation and decide on `private_key_jwt`
**Target:** CONTRACTS 12.3, "CIMD" bullet; O1 brief, "CIMD" bullet and its acceptance test.

**Why:**
- The MCP spec requires an https `client_id` with a path. The document must be valid JSON with `client_id`, `client_name` and `redirect_uris`. The AS MUST check that `client_id` equals the URL exactly ([implementation requirements](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#implementation-requirements)).
- CIMD draft -02 adds the following ([draft -02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02)):
  - no dot segments in the URL
  - simple string comparison, with no default-port normalization
  - only a 200 response counts
  - no shared-secret fields or symmetric client authentication in the document
  - no caching of errors or invalid documents
  - a read limit of about 5 KB
- Clients MAY authenticate with `private_key_jwt`. FastMCP already meets such clients ([#4789](https://github.com/PrefectHQ/fastmcp/issues/4789)).

**Change (CONTRACTS 12.3):**
```diff
 - **CIMD (client ID metadata documents):**
-  - A `client_id` that is an https URL is fetched, with a 5s timeout, a 64 KB size cap and caching by HTTP cache headers.
-  - Its `client_id` field must equal the URL.
-  - Its redirect URIs are then trusted.
-  - Private, loopback and link-local IPs (checked after DNS resolution) are rejected (SSRF guard).
+  - A `client_id` that is an https URL with a non-empty path, no fragment, no userinfo and no `.` or `..` segments is fetched. Fetch limits: a 5s timeout, no redirects, a 5 KB read limit, and only HTTP 200 accepted. Valid documents are cached by HTTP cache headers within fixed bounds; errors and invalid documents are never cached.
+  - The document must be a JSON object whose `client_id` equals the URL by simple string comparison. It must have `client_name` and a non-empty `redirect_uris`, each meeting the redirect rule above.
+  - It must not contain `client_secret` or `client_secret_expires_at`. Its `token_endpoint_auth_method` must be absent or `none`; `private_key_jwt` is rejected with `invalid_client` in v0.1 (a later version may add it). `grant_types` may only contain `authorization_code` and `refresh_token`.
+  - Private, loopback, link-local, unique-local, multicast and IPv4-mapped addresses (checked after DNS resolution) are rejected (SSRF guard).
```
**O1 acceptance test change:** "> 64 KB rejected" becomes "> 5 KB rejected". Add:
- a document with `client_secret` is rejected
- a document with `token_endpoint_auth_method: private_key_jwt` is rejected with `invalid_client`
- a URL with `/../` is rejected
- a 404 is not cached

**Record (O1 README):** "MCP authorization 2026-07-28; CIMD per draft-00 as cited, with the stricter draft-02 checks."

## 5. Show the redirect host on the consent screen
**Target:** O1 brief, "Consent" bullet (HTML page and JSON mode).

**Why:**
- The AS **MUST** clearly display the redirect URI hostname during authorization, and **SHOULD** warn when a client has only `localhost` redirect URIs ([localhost redirect URI risks](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#localhost-redirect-uri-risks)).
- O1 currently shows the CIMD host (the `client_id` host), which is a different value.

**Change:**
```diff
-  ... Else accessible HTML (no JavaScript, client name, CIMD host, scopes, `frame-ancestors 'none'`) or redirect to `consent_page`. JSON mode (D2 `ConsentScreen`): `Accept: application/json` -> `{consent_id, client, scopes, resource}` or `{url}`.
+  ... Else accessible HTML (no JavaScript, client name, CIMD host, the redirect URI host of this request, a warning when every redirect URI of the client is loopback, scopes, `frame-ancestors 'none'`) or redirect to `consent_page`. JSON mode (D2 `ConsentScreen`): `Accept: application/json` -> `{consent_id, client, scopes, resource, redirect_host, loopback_only}` or `{url}`.
```
**Follow-on for D2:** `ConsentScreen` renders `redirect_host` and the warning.

**Recommended, not required by the spec** (the spec allows extra attestation): do not issue a code from stored consent on GET for a CIMD client whose redirect URI is loopback. Any local program can claim such a client, so showing the screen again is the safer default.

## 6. Accept and check `resource` at the token endpoint
**Target:** CONTRACTS 12.3, "Resource indicators" bullet; O1 brief, "Authorize" and "Grants" bullets.

**Why:**
- Clients MUST send `resource` in both authorization **and** token requests ([resource parameter](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation)), refresh requests included. Clients already do this: python-sdk [#2578](https://github.com/modelcontextprotocol/python-sdk/issues/2578).
- Servers SHOULD accept uppercase scheme and host ([canonical server URI](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#canonical-server-uri)).
- A path-matching bug became an auth bypass in python-sdk [#3303](https://github.com/modelcontextprotocol/python-sdk/issues/3303).

**Change (CONTRACTS 12.3):**
```diff
-- **Resource indicators:** `resource` binds tokens to an audience; a token for one MCP server can't be used at another.
+- **Resource indicators (RFC 8707):** `resource` binds tokens to an audience; a token for one MCP server can't be used at another.
+  - At authorize: at most one `resource`, and it must be in `resources`. Otherwise the client is redirected with `error=invalid_target` (after the client and `redirect_uri` checks pass).
+  - At the token endpoint (`authorization_code` and `refresh_token`): `resource` is optional. When present, it must equal the resource bound to the code or grant, else `invalid_target`. Refreshed tokens keep the original `aud`.
+  - Comparison: lowercase the scheme and host, drop a default port, and compare the path exactly. URIs with a fragment or dot segments are rejected. `resources` entries are normalized the same way when `GotAuth(...)` is constructed.
```
**Acceptance tests (O1):**
- `resource=HTTPS://MCP.EXAMPLE.COM/mcp` matches `https://mcp.example.com/mcp`.
- `/mcp/../admin` is rejected.
- A token request with a different `resource` gets `invalid_target`.
- A refresh with the same `resource` works.

## 7. Test that the issuer is exact
**Target:** O1 brief, acceptance tests.

**Why:**
- Clients MUST reject metadata whose `issuer` is not identical to the issuer used to build the well-known URL ([AS metadata discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#authorization-server-metadata-discovery)).
- Trailing slashes and subpaths broke real servers: python-sdk [#1919](https://github.com/modelcontextprotocol/python-sdk/issues/1919), FastMCP [#4390](https://github.com/PrefectHQ/fastmcp/issues/4390).

**Change (O1 acceptance test):**
```diff
-- `auth.well_known()` serves `/.well-known/oauth-authorization-server/api/auth`; `/api/auth/.well-known/openid-configuration` has the same `issuer`.
+- `auth.well_known()` serves `/.well-known/oauth-authorization-server/api/auth`; `/api/auth/.well-known/openid-configuration` has the same `issuer`. That `issuer` is string-identical to `base_url + base_path` with no trailing slash, to the access token `iss`, and to the authorization response `iss`, including when `base_url` was configured with a trailing slash.
```

## 8. Require HTTPS when MCP mode is on
**Target:** O1 brief, `oauth_provider(...)` bullet.

**Why:** all authorization server endpoints MUST be served over HTTPS ([communication security](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#communication-security)).

**Change:**
```diff
-... `resources`: allowed audiences besides the issuer; `mcp=True` requires `resource` and CIMD.
+... `resources`: allowed audiences besides the issuer; `mcp=True` requires `resource` and CIMD, and raises `ConfigError` at construction when `base_url` is not `https` (a loopback host is allowed for local development).
```

## 9. Fill in the MCP-side `WWW-Authenticate` challenges
**Target:** CONTRACTS 12.4 (comments under `fastmcp_auth` and `protected_resource_metadata`); O2 brief, "Verification" bullets and acceptance tests.

**Why:**
- On 401, servers SHOULD include `scope` next to `resource_metadata` ([scope selection strategy](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#scope-selection-strategy)).
- On 403 they SHOULD send `error="insufficient_scope"`, every scope the operation needs, and `resource_metadata` ([runtime insufficient scope](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#runtime-insufficient-scope-errors)).
- Protected resource metadata SHOULD NOT list `offline_access` ([refresh tokens](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#refresh-tokens)).
- Both Python SDKs shipped this wrong: FastMCP [#4513](https://github.com/PrefectHQ/fastmcp/issues/4513), python-sdk [#3103](https://github.com/modelcontextprotocol/python-sdk/issues/3103). So O2 should set or test the header itself and not assume the framework does.

**Change (O2 brief):**
```diff
-  - Missing scope -> 403, `WWW-Authenticate: Bearer error="insufficient_scope", scope="..."`. Missing or bad token -> 401 with `resource_metadata="<url>"`.
+  - Missing scope -> 403, `WWW-Authenticate: Bearer error="insufficient_scope", scope="<all scopes the call needs>", resource_metadata="<url>"`.
+  - Missing token -> 401, `WWW-Authenticate: Bearer resource_metadata="<url>", scope="<configured scopes>"` (`scope` omitted when none are configured).
+  - Bad or expired token -> the same, plus `error="invalid_token"`.
```
**Change (CONTRACTS 12.4):**
```diff
 def protected_resource_metadata(*, resource: str, issuer: str, scopes: Sequence[str]) -> dict[str, Any]: ...
+# scopes_supported never contains "offline_access" (MCP 2026-07-28, Refresh Tokens).
```
**Acceptance tests (O2):**
- The 401 and 403 headers match the lines above, byte for byte, for FastMCP and the MCP SDK.
- `protected_resource_metadata(scopes=["projects:read", "offline_access"])` lists only `projects:read`.

## 10. Say that scopes are flat
**Target:** CONTRACTS 12.1, "Field rules".

**Why:** "Servers **MUST** account for scope hierarchies" ([step-up flow](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#step-up-authorization-flow)). GotAuth's `has_scopes` is exact containment. That is compliant only while no scope implies another, so it should be stated.

**Change:**
```diff
 - **Permissions and scopes** share one vocabulary: the scope `"project:delete"` is the permission `{"project": ["delete"]}`. P5's `has_permission` and A1's `require(...)` both use this mapping.
+- **Scopes are flat.** No scope implies another (`projects:write` does not grant `projects:read`), so `has_scopes` is exact containment. Apps that want a hierarchy request both scopes, and that hierarchy is out of scope for v0.1.
```

## Notes for O2 (no contract change)
- **Current versions** ([PyPI](https://pypi.org/pypi/fastmcp/json), [PyPI](https://pypi.org/pypi/mcp/json)): `fastmcp` 4.0.10 (2026-09-25) and `mcp` 2.3.0 (2026-10-02). These match the brief's "FastMCP 4.x, `mcp` 2.x".
- **Stateless protocol.** Revision 2026-07-28 removes `initialize` and `Mcp-Session-Id` ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)). O2's in-memory client tests should use the stateless request form those versions expose.
- **Enterprise-managed authorization** (SEP-990, the identity assertion grant) is an extension, not core. FastMCP and the MCP Python SDK support it ([SDK docs](https://py.sdk.modelcontextprotocol.io/run/authorization/), [FastMCP OAuth proxy](https://gofastmcp.com/servers/auth/oauth-proxy)). It had the largest public signal in R1 (HN 278 points; python-sdk #1593, 10 reactions). It is not part of v0.1; it is a candidate for O4 or later.

## Status
Applied by the integrator on 2026-10-04 in branch chore/apply-r1-requests.

Applied differently or added, and why:
- Item 1: the O1 test checks that both documents contain every listed key, not "exactly these keys", because the diff says "at least" and OIDC Discovery 1.0 requires `subject_types_supported` and `id_token_signing_alg_values_supported` (now named in the brief).
- Item 1: CONTRACTS 12.3 had no diff for the `oauth_server_metadata` row, so it gained a "Discovery metadata" rule with the same keys and the exact-issuer rule from item 7.
- Item 3: the redirect rule also applies at `update_oauth_client`, because its 12.5 shape takes `redirect_uris`.
- Item 4: Q1's CIMD SSRF test now says > 5 KB, so it matches the new read limit.
- Item 5, recommended part: written as a 12.3 rule keyed on the request's `redirect_uri` being loopback, which covers every CIMD client with only loopback redirects and also closes the same gap for clients that mix https and loopback.
- Item 6: CONTRACTS also says the matching normalized `resources` entry becomes `aud`, so O2's `aud` check has one form to compare.
- Item 7: CONTRACTS 12.2 now says the `iss` claim has no trailing slash and equals the metadata `issuer`.
- Item 8: added an O1 acceptance test and an O2 note to set `base_url` to the tunnel URL, since the example uses `mcp=True`.
- Item 9: the bad-token header puts `error="invalid_token"` first so the byte-for-byte test has one form, and `offline_access` is also left out of challenge `scope` values, as the spec says for challenges.
- Item 9: CONTRACTS 12.4 lists the three challenges as comments under `fastmcp_auth`, since the request named that spot but gave no diff.
- Notes for O2: added to the O2 brief's Notes (versions, stateless protocol, SEP-990 out of v0.1).
