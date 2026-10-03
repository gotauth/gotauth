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
- `oauth_provider(*, login_page="/sign-in", consent_page=None, scopes=("openid","profile","email","offline_access"), resources=(), access_token_ttl="10m", refresh_token_ttl="30d", signing_alg="ES256", allow_cimd=True, allow_dynamic_registration=False, mcp=False)`, id `"oauth_provider"`, `from gotauth.plugins.oauth_provider import oauth_provider`. `resources`: allowed audiences besides the issuer; `mcp=True` requires `resource` and CIMD.
- The five O1 models exactly as 12.2, prefixes `cli`, `ocn`, `cod`, `tok`, `jwk`. `oauth_token.refresh_token_hash` and `user_id` are optional; `parent_id` stays unset until O4.
- Endpoints: ids, paths and auth exactly as 12.3.
  - `oauth_consent`: `input_format="form"`. `oauth_token`, `oauth_introspect`, `oauth_revoke`: `input_format="form"`, `error_format="oauth"` (C1 renders every error, pipeline errors included, per RFC 6749).
  - `oauth_userinfo`: own check (any audience, `openid` scope), RFC 6750 errors. `oauth_register` only if enabled (public clients, `registration="dynamic"`).
  - Discovery: `oauth_openid_configuration` inside the mount; `oauth_server_metadata` in `Plugin.well_known_endpoints`, at the host root via `auth.well_known()` (RFC 8414 path insertion). Same metadata, incl. `code_challenge_methods_supported: ["S256"]` and CIMD support.
  - server_only (`/oauth2/clients`, `/oauth2/keys`, `/oauth2/tokens`): `update_oauth_client` covers `agent_id` and disabled; `revoke_oauth_tokens` by client, user, agent or family; `verify_access_token` checks signature, claims and revocation and returns the `Principal` (for O2).
- Authorize: `response_type=code`; PKCE S256 required (missing or `plain` -> `invalid_request`); exact `redirect_uri`, loopback any port (RFC 8252); bad client or redirect_uri -> HTML error, never a redirect; `state`, `nonce`, `prompt`; `iss` in the response (RFC 9207); scopes within client and server scopes; `resource` in `resources` (RFC 8707; absent -> `aud` = issuer). No session -> `login_page?callback_url=<authorize URL>`.
- Consent: a stored `oauth_consent` covering client, scopes and resource -> code issued on the GET (allowed exception, 12.3). Else accessible HTML (no JavaScript, client name, CIMD host, scopes, `frame-ancestors 'none'`) or redirect to `consent_page`. JSON mode (D2 `ConsentScreen`): `Accept: application/json` -> `{consent_id, client, scopes, resource}` or `{url}`. `consent_id` = `crypto.sign` (purpose `"oauth_consent"`, 10m; nothing written on GET) over the request, bound to the session user. The form posts `consent_id`, `accept`, `scopes?`. Emits `oauth.consent_granted`.
- Codes `gac_`: hashed, 60s, single use (`delete(...) == 1`); their tokens get `family_id = code_hash`, so a replayed code revokes them.
- Grants (registry keyed by `grant_type`, for O4): `authorization_code` (`crypto.pkce_s256` + `crypto.equal`); `refresh_token` (`gar_`, hashed, rotated, scope only narrows, reuse of a rotated or revoked token revokes the family); `client_credentials` (confidential only, no refresh token; `sub` = the client's agent id, else the client id; row `user_id` = the agent's owning user if user-owned, else None). Client auth: `client_secret_basic`, `client_secret_post`, `none` (public).
- Access tokens per 12.2 (`typ at+jwt`, ES256, `aud` = resource or issuer, `jti` = `oauth_token` id, `act` if the client has `agent_id`). ID token when `openid` is granted (`aud` = client_id, `nonce`, `auth_time`).
- `PrincipalResolver`, `prefixes=("eyJ",)`: algorithm pinned per `kid`; check `typ`, `iss`, `exp`, `aud` in (issuer, `base_url`); `credential_id` = `jti`, `user_id` from the token row (never an agent or client id), `client_id`, `agent_id` (from `act`), `scopes`. Ban checks are P6's `PrincipalCheck`.
- Revocation (12.2): the resolver and `verify_access_token` look up `jti` and reject revoked tokens, disabled clients and agents. O1's own revocations clear the optional <= 5s cache.
- Introspection (RFC 7662, confidential clients; O2 `introspect=True`); revocation (RFC 7009: 200 for unknown, own tokens only; emits `oauth.token_revoked`).
- CIMD: https, no fragment or userinfo; resolve DNS and reject private, loopback, link-local, unique-local, multicast, IPv4-mapped; connect to the vetted IP; no redirects; 5s; 64 KB; bounded caching; `client_id` == URL; auth `none`; `registration="cimd"`.
- Keys: created in `init` if none, private key `crypto.encrypt(purpose="jwk_private")`; retired keys stay in JWKS until `retired_at + access_token_ttl`. Client secrets: `crypto.random_token("gcs_")`, hashed, shown once. New clients emit `oauth.client_created`.
- `create_oauth_client`, `update_oauth_client`, `revoke_oauth_tokens` and `verify_access_token` take and return exactly the CONTRACTS 12.5 shapes. `verify_access_token` returns `{valid, code?, principal?}`; O2 and O3 depend on it.

## Acceptance tests
- Full code + PKCE flow with consent and refresh. Missing/`plain` PKCE, wrong verifier, redirect tricks (trailing slash, case, extra query, other host, fragment) rejected; loopback any port accepted.
- Code reuse -> `invalid_grant` + its tokens revoked; refresh reuse revokes the family; Hypothesis: issued scopes always within granted.
- Token for resource A rejected at B; unknown `resource` rejected; none -> `aud` = issuer.
- `client_credentials`: confidential ok, public rejected, no refresh token, `Principal.user_id` = owning user or None. Introspection inactive after revoke.
- Token endpoint: JSON body, bad client and rate limit all answer in RFC 6749 shape.
- Revoke -> resolver and `verify_access_token` reject on the next call, no clock advance.
- `auth.well_known()` serves `/.well-known/oauth-authorization-server/api/auth`; `/api/auth/.well-known/openid-configuration` has the same `issuer`.
- CIMD (mocked DNS, respx): valid doc ok; private/loopback/link-local IP, redirect, > 64 KB, timeout, `client_id` mismatch rejected.
- Consent remembered; `prompt=consent` forces it; page has no `<script>`; forged, expired or other-user `consent_id` rejected.
- `alg: none`, HS256 signed with the public key, unknown `kid`, ID token used as access token: rejected. DB dump: no raw `gac_`, `gar_`, `gcs_` or plain private key.

## Out of scope
MCP helpers (O2), agent endpoints (O3), token exchange (O4), consent component (D2), conformance runs (Q1).

## Notes
- `invalid_client` is 401 + `WWW-Authenticate`. Remote JWT-only resource servers accept a revoked token until expiry (12.2): document it with O2's `introspect=True`.
- Ship `conformance/` (app factory + OpenID conformance plan config) for Q1; no PKCE bypass, record plans that need one.
- Target MCP authorization spec 2026-07-28: read the text (R1); record it and the CIMD draft version.
