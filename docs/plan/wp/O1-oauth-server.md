# O1: OAuth 2.1 authorization server + OIDC provider

| | |
|---|---|
| Lane / wave | Agent and OAuth / **Wave 2 -> 3** |
| Size | L |
| Depends on | C1-C3 (C1: form input, `error_format="oauth"`, `auth.well_known()`) |
| Can start | after M1; keys, tokens and CIMD earlier against `gotauth.testing` |
| Write scope | `src/gotauth/plugins/oauth_provider/**`, `tests/plugins/oauth_provider/**`, `changes/O1.*.md` |
| Allowed new deps | none |

## Goal
An embeddable OAuth 2.1 server and OIDC provider on the app's own users, so MCP clients can log in to Python MCP servers (12.2, 12.3).

## Build
- `oauth_provider(*, login_page="/sign-in", consent_page=None, scopes=("openid","profile","email","offline_access"), resources=(), access_token_ttl="10m", refresh_token_ttl="30d", signing_alg="ES256", allow_cimd=True, allow_dynamic_registration=False, mcp=False)`, id `"oauth_provider"`, `from gotauth.plugins.oauth_provider import oauth_provider`. `resources`: allowed audiences besides the issuer; `mcp=True` requires `resource` and CIMD, and raises `ConfigError` at construction when `base_url` is not `https` (a loopback host is allowed for local development).
- The five O1 models exactly as 12.2, prefixes `cli`, `ocn`, `cod`, `tok`, `jwk`. `oauth_token.refresh_token_hash` and `user_id` are optional; `parent_id` stays unset until O4.
- Endpoints: ids, paths and auth exactly as 12.3.
  - `oauth_consent`: `input_format="form"`. `oauth_token`, `oauth_introspect`, `oauth_revoke`: `input_format="form"`, `error_format="oauth"` (C1 renders every error, pipeline errors included, per RFC 6749).
  - `oauth_userinfo`: own check (any audience, `openid` scope), RFC 6750 errors. `oauth_register` only if enabled (public clients, `registration="dynamic"`, `application_type` required per the 12.3 redirect rule).
  - Discovery: `oauth_openid_configuration` inside the mount; `oauth_server_metadata` in `Plugin.well_known_endpoints`, at the host root via `auth.well_known()` (RFC 8414 path insertion). Both serve the same document with at least: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`, `scopes_supported`, `response_types_supported: ["code"]`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported: ["S256"]`, `authorization_response_iss_parameter_supported: true`, and `client_id_metadata_document_supported: true` when `allow_cimd`. `registration_endpoint` appears only when `allow_dynamic_registration`. Both also carry the other keys OpenID Connect Discovery 1.0 requires (`subject_types_supported`, `id_token_signing_alg_values_supported`).
  - server_only (`/oauth2/clients`, `/oauth2/keys`, `/oauth2/tokens`): `update_oauth_client` covers `agent_id` and disabled; `revoke_oauth_tokens` by client, user, agent or family; `verify_access_token` checks signature, claims and revocation and returns the `Principal` (for O2).
- Authorize: `response_type=code`; PKCE S256 required (missing or `plain` -> `invalid_request`); `redirect_uri` per the 12.3 redirect rule (`https`, or `http` on a loopback host; exact match, except that a loopback port may differ, RFC 8252 section 7.3); bad client or redirect_uri -> HTML error, never a redirect; `state`, `nonce`, `prompt`; `iss` on every redirect to the client, success and error alike (RFC 9207 section 2), equal to the metadata `issuer`; scopes within client and server scopes; at most one `resource`, in `resources` after the 12.3 normalization (RFC 8707; absent -> `aud` = issuer; otherwise a redirect with `error=invalid_target`). No session -> `login_page?callback_url=<authorize URL>`.
- Consent: a stored `oauth_consent` covering client, scopes and resource -> code issued on the GET (allowed exception, 12.3), unless the client is a CIMD client and this request's `redirect_uri` is loopback (12.3: any local program can claim such a client, so the screen is shown again). Else accessible HTML (no JavaScript, client name, CIMD host, the redirect URI host of this request, a warning when every redirect URI of the client is loopback, scopes, `frame-ancestors 'none'`) or redirect to `consent_page`. JSON mode (D2 `ConsentScreen`): `Accept: application/json` -> `{consent_id, client, scopes, resource, redirect_host, loopback_only}` or `{url}`. `consent_id` = `crypto.sign` (purpose `"oauth_consent"`, 10m; nothing written on GET) over the request, bound to the session user. The form posts `consent_id`, `accept`, `scopes?`. Emits `oauth.consent_granted`.
- Codes `gac_`: hashed, 60s, single use (`delete(...) == 1`); their tokens get `family_id = code_hash`, so a replayed code revokes them.
- Grants (registry keyed by `grant_type`, for O4): `authorization_code` (`crypto.pkce_s256` + `crypto.equal`); `refresh_token` (`gar_`, hashed, rotated, scope only narrows, reuse of a rotated or revoked token revokes the family); `client_credentials` (confidential only, no refresh token; `sub` = the client's agent id, else the client id; row `user_id` = the agent's owning user if user-owned, else None). Client auth: `client_secret_basic`, `client_secret_post`, `none` (public). `authorization_code` and `refresh_token` accept an optional `resource`: when present it must equal the resource bound to the code or grant (12.3 comparison), else `invalid_target`; refreshed tokens keep the original `aud`.
- Access tokens per 12.2 (`typ at+jwt`, ES256, `aud` = resource or issuer, `jti` = `oauth_token` id, `act` if the client has `agent_id`). ID token when `openid` is granted (`aud` = client_id, `nonce`, `auth_time`).
- `PrincipalResolver`, `prefixes=("eyJ",)`: algorithm pinned per `kid`; check `typ`, `iss`, `exp`, `aud` in (issuer, `base_url`); `credential_id` = `jti`, `user_id` from the token row (never an agent or client id), `client_id`, `agent_id` (from `act`), `scopes`. Ban checks are P6's `PrincipalCheck`.
- Revocation (12.2): the resolver and `verify_access_token` look up `jti` and reject revoked tokens, disabled clients and agents. O1's own revocations clear the optional <= 5s cache.
- Introspection (RFC 7662, confidential clients; O2 `introspect=True`); revocation (RFC 7009: 200 for unknown, own tokens only; emits `oauth.token_revoked`).
- CIMD (12.3): https with a non-empty path, no fragment, no userinfo, no `.` or `..` segments; resolve DNS and reject private, loopback, link-local, unique-local, multicast, IPv4-mapped; connect to the vetted IP; no redirects; 5s; 5 KB read limit; HTTP 200 only; valid documents cached by HTTP headers within fixed bounds, errors and invalid documents never cached. The document: a JSON object, `client_id` == URL (simple string comparison), `client_name`, non-empty `redirect_uris` that meet the redirect rule; no `client_secret` or `client_secret_expires_at`; `token_endpoint_auth_method` absent or `none` (`private_key_jwt` -> `invalid_client` in v0.1); `grant_types` only `authorization_code` and `refresh_token`. Auth `none`; `registration="cimd"`.
- Keys: created in `init` if none, private key `crypto.encrypt(purpose="jwk_private")`; retired keys stay in JWKS until `retired_at + access_token_ttl`. Client secrets: `crypto.random_token("gcs_")`, hashed, shown once. New clients emit `oauth.client_created`.
- `create_oauth_client`, `update_oauth_client`, `revoke_oauth_tokens` and `verify_access_token` take and return exactly the CONTRACTS 12.5 shapes. `verify_access_token` returns `{valid, code?, principal?}`; O2 and O3 depend on it.

## Acceptance tests
- Full code + PKCE flow with consent and refresh. Missing/`plain` PKCE, wrong verifier, redirect tricks (trailing slash, case, extra query, other host, fragment) rejected; loopback any port accepted.
- Redirect URIs: `http://example.com/cb` is rejected at client creation; `http://localhost:5555/cb` matches a registered `http://localhost:3000/cb`; `http://127.0.0.1.nip.io/cb` is not treated as loopback.
- `iss`: a denied consent and an `invalid_scope` redirect both carry `iss`.
- Code reuse -> `invalid_grant` + its tokens revoked; refresh reuse revokes the family; Hypothesis: issued scopes always within granted.
- Token for resource A rejected at B; unknown `resource` rejected; none -> `aud` = issuer.
- Resource comparison: `resource=HTTPS://MCP.EXAMPLE.COM/mcp` matches `https://mcp.example.com/mcp`; `/mcp/../admin` is rejected; a token request with a different `resource` gets `invalid_target`; a refresh with the same `resource` works.
- `client_credentials`: confidential ok, public rejected, no refresh token, `Principal.user_id` = owning user or None. Introspection inactive after revoke.
- Token endpoint: JSON body, bad client and rate limit all answer in RFC 6749 shape.
- Revoke -> resolver and `verify_access_token` reject on the next call, no clock advance.
- `auth.well_known()` serves `/.well-known/oauth-authorization-server/api/auth`; `/api/auth/.well-known/openid-configuration` has the same `issuer`. That `issuer` is string-identical to `base_url + base_path` with no trailing slash, to the access token `iss`, and to the authorization response `iss`, including when `base_url` was configured with a trailing slash.
- Discovery: both documents are identical and contain every key in the Discovery list above; `registration_endpoint` is absent by default and present when DCR is on.
- `oauth_provider(mcp=True)` with `base_url="http://example.com"` raises `ConfigError`; `http://localhost:8000` is accepted.
- CIMD (mocked DNS, respx): valid doc ok; private/loopback/link-local IP, redirect, > 5 KB, timeout, `client_id` mismatch rejected. Also rejected: a document with `client_secret`; a document with `token_endpoint_auth_method: private_key_jwt` (`invalid_client`); a URL with `/../`. A 404 is not cached.
- Consent remembered; `prompt=consent` forces it; page has no `<script>`; forged, expired or other-user `consent_id` rejected.
- Consent shows the redirect URI host of the request in HTML and JSON (`redirect_host`), and the loopback-only warning (`loopback_only: true`) only when every redirect URI of the client is loopback. With stored consent, a CIMD client on a loopback `redirect_uri` gets the consent screen again and no code on the GET; a static client on the same redirect still gets the code.
- `alg: none`, HS256 signed with the public key, unknown `kid`, ID token used as access token: rejected. DB dump: no raw `gac_`, `gar_`, `gcs_` or plain private key.

## Out of scope
MCP helpers (O2), agent endpoints (O3), token exchange (O4), consent component (D2), conformance runs (Q1).

## Notes
- `invalid_client` is 401 + `WWW-Authenticate`. Remote JWT-only resource servers accept a revoked token until expiry (12.2): document it with O2's `introspect=True`.
- Ship `conformance/` (app factory + OpenID conformance plan config) for Q1; no PKCE bypass, record plans that need one.
- Target MCP authorization spec 2026-07-28. R1 read the text and compared it with this brief (`docs/research/validation-research.md`, MCP auth addendum, section 2). Record in the module README: "MCP authorization 2026-07-28; CIMD per draft-00 as cited, with the stricter draft-02 checks."
