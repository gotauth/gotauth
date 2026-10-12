# Threat model

STRIDE per flow for GotAuth as of 2026-10-10 (main after O1). Each mitigation names the CONTRACTS section that requires it and the test that proves it. A mitigation without a test links the open request instead.

Test paths are relative to the repository root. `sec/` is short for `tests/security/`.

## Scope and trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| HTTP | GotAuth pipeline and handlers | Browsers, API clients, agents, OAuth clients |
| Storage | The adapter, the database, secondary storage | Anyone with a database dump or backup (sees hashes only) |
| Outbound HTTP | GotAuth | Social providers, JWKS endpoints, CIMD documents |
| Email | The sender configured by the app | Mailboxes (links can leak through forwarding or logs) |
| Host app | The app that mounts GotAuth and owns `secret` | n/a: an attacker with code execution in the app is out of scope |

**Assets:** password hashes, session tokens (`gas_`), API keys (`gak_`), refresh tokens (`gar_`), authorization codes (`gac_`), email tokens (`gav_`), client secrets (`gcs_`), JWT signing keys, provider tokens, and the user and account rows.

**Common controls** (apply to every flow below):
- **Hashed secrets.** Every bearer secret is stored only as a hash (CONTRACTS 7, 8). Test: `sec/test_raw_tokens.py::test_full_scenario_leaves_no_secret_behind`, with a self-test `test_scan_catches_a_raw_token_stored_on_purpose`.
- **Origin check and content type.** Cookie writes need a trusted `Origin` or `Referer`, and JSON endpoints refuse other content types (10.1). Tests: `sec/test_requests.py::test_cookie_posts_need_a_trusted_origin`, `test_form_posts_to_json_endpoints_are_refused`.
- **Rate limits.** On by default, and they ignore `X-Forwarded-For` unless `trusted_proxies` is set (10.2). Tests: `sec/test_limits_and_replay.py::test_sign_in_limit_with_retry_after`, `test_forwarded_ips_count_only_from_trusted_proxies`, `test_per_email_limits_hold_across_rotating_ips`.
- **Errors.** No input values in errors, no 500 with details (6). Tests: `sec/test_fuzz.py::test_every_endpoint_survives_fuzzed_input`, `tests/core/test_pipeline.py::test_unexpected_errors_are_500_without_details`.
- **Redirects.** Every redirect parameter goes through `validate_redirect` (10.1). Tests: `sec/test_requests.py::test_open_redirects_are_refused`, `test_wildcard_does_not_match_the_bare_domain_or_lookalikes`.

## 1. Email and password (C2)

**Assets:** passwords, `gav_` reset and verification tokens, email ownership.
**Boundaries:** browser to `/sign-up/email`, `/sign-in/email`, `/request-password-reset`, `/reset-password`, `/verify-email`; GotAuth to the mailbox.

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| S | Credential stuffing, brute force | Per IP+path and per-email limits (10.2); scrypt `ln=15, r=8, p=3` (8) | `sec/test_limits_and_replay.py::test_per_email_limits_hold_across_rotating_ips` |
| S | Pre-account hijack: attacker signs up with the victim's email first | Unverified accounts can be claimed by the real owner; reset requires email proof (9.1, C2) | `tests/email_password/test_flows.py::test_abandoned_unverified_sign_up_can_be_claimed`, `test_reset_password_verifies_the_email` |
| T | Reuse of a reset or verification link | Single use, hashed, kind-bound, expiry 1h / 24h (9) | `sec/test_limits_and_replay.py::test_verification_and_reset_tokens_work_once`, `tests/email_password/test_flows.py::test_concurrent_resets_with_one_token_succeed_once` |
| R | User denies a password change | `password.changed` event and a security notice email (9, 14) | `tests/email_password/test_flows.py::test_change_password` |
| I | Account enumeration by body or status | Same body for known and unknown emails (9.1) | `sec/test_enumeration.py::test_same_status_and_body_for_known_and_unknown_emails` |
| I | Account enumeration by timing | Dummy hash on sign-in (9.1); background email (9) | `sec/test_enumeration.py::test_timing_does_not_reveal_accounts` (sign-in passes; reset and verification are xfail, see [Q1-C2-timing](../requests/Q1-C2-timing.md)) |
| I | Password in logs or errors | Never logged or echoed (8) | `tests/email_password/test_flows.py::test_passwords_never_leak` |
| D | Very long passwords as a CPU attack | Max 128 characters, checked before hashing (8) | `tests/email_password/test_flows.py::test_over_long_password_is_not_hashed` |
| E | Session survives a password reset | Reset revokes all sessions by default (7) | `tests/email_password/test_flows.py::test_reset_password_revokes_sessions_by_default` |

**Residual risk:**
- The reset and verification timing gap ([Q1-C2-timing](../requests/Q1-C2-timing.md)).
- No common or breached password check, and `change_email` without a fresh session ([Q1-C2-asvs-gaps](../requests/Q1-C2-asvs-gaps.md)).

## 2. Sessions (C3)

**Assets:** `gas_` tokens, the signed cookie cache.
**Boundaries:** browser cookie or bearer header to the pipeline; GotAuth to secondary storage.

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| S | Session fixation: a planted cookie is adopted at sign-in | Every sign-in creates a new token (7) | `sec/test_requests.py::test_a_planted_session_cookie_is_never_adopted`, `tests/sessions/test_service.py::test_each_create_makes_a_new_token_even_when_one_is_presented` |
| S | Token theft through script or plain HTTP | `HttpOnly`, `Secure`, `SameSite=Lax`, `__Secure-` prefix on https (7) | `sec/test_requests.py::test_cookie_flags_on_https`, `tests/sessions/test_service.py::test_cookie_attributes` |
| T | Forged or swapped cookie cache | HMAC over the cache, bound to the token hash (`th`) (7) | `tests/sessions/test_service.py::test_tampered_cache_is_ignored`, `test_cache_only_works_with_its_own_token` |
| T | CSRF on session endpoints | Origin check (10.1) | `sec/test_requests.py::test_cookie_posts_need_a_trusted_origin` |
| I | Token readable from a database dump | Only the hash is stored (7) | `tests/sessions/test_service.py::test_no_raw_token_anywhere_after_the_full_lifecycle` |
| D | Session table growth | Expired rows deleted on read (7) | `tests/sessions/test_service.py::test_expired_sessions_are_deleted` |
| E | Revoked session still accepted | Revocation is checked on every database read; cache max 5 minutes (7) | `tests/sessions/test_service.py::test_secondary_storage_caches_by_hash_and_forgets_on_revoke`, `tests/sessions/test_http.py::test_revoked_bearer_is_unauthenticated` |

**Residual risk:** with the cookie cache on (off by default), a revoked session can be used until the cache expires, at most `cookie_cache.max_age` (5 minutes; CONTRACTS 7).

## 3. Social login (C4)

**Assets:** the link between a provider identity and a user, provider tokens.
**Boundaries:** browser to the provider and back to `/callback/{provider}`; GotAuth to the token, userinfo and JWKS endpoints.

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| S | Login CSRF: attacker's callback in the victim's browser | `state` bound to a cookie, single use, provider-bound (11) | `tests/social/test_flow.py::test_cookie_for_another_state_is_rejected`, `test_reused_state_is_rejected`, `test_state_of_another_provider_is_rejected` |
| S | Code interception | PKCE on every provider (11) | `tests/social/test_flow.py::test_new_user_signs_in_and_pkce_is_checked` |
| S | Takeover through an unverified provider email | Linking only on a verified email; a trusted claim removes unproven links and the password (11) | `tests/social/test_flow.py::test_linking_matrix`, `test_trusted_claim_removes_every_unproven_link` |
| T | Forged ID token | Signature, `iss`, `aud`, `exp`, `nonce` checked against the JWKS (11) | `tests/social/test_providers.py::test_bad_id_tokens_are_rejected`, `test_microsoft_common_checks_the_tenant_issuer` |
| I | Provider tokens leaked from the database | Not stored by default; AES-GCM when stored (11) | `tests/social/test_flow.py::test_provider_tokens_are_not_stored_by_default`, `test_provider_tokens_are_stored_encrypted_with_the_flag` |
| D | Slow or broken provider | httpx timeouts; errors become `PROVIDER_ERROR` (11) | `tests/social/test_providers.py::test_token_endpoint_errors_are_provider_errors` |
| E | Unlinking the last way to sign in | Refused for social-only users (11) | `tests/social/test_flow.py::test_a_social_only_user_cannot_unlink_the_last_provider` |

**Residual risk:** account security depends on each provider's email verification. GitHub uses the primary verified email only (`test_github_uses_the_primary_verified_email`).

## 4. OAuth 2.1 server and OIDC provider (O1)

**Assets:** codes, access tokens (JWT), refresh tokens, client secrets, signing keys, consents.
**Boundaries:** OAuth clients (static, CIMD, DCR) to `/oauth2/*`; GotAuth to CIMD URLs.

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| S | Code interception | PKCE S256 required; `plain` refused (12.3) | `tests/plugins/oauth_provider/test_flow.py::test_pkce_is_required_and_checked` |
| S | Code sent to the attacker through `redirect_uri` | Exact match against registered URIs; error page instead of a redirect (12.3) | `sec/test_oauth.py::test_unregistered_redirects_never_receive_a_redirect`, `tests/plugins/oauth_provider/test_flow.py::test_redirect_tricks_get_an_error_page` |
| S | Code used with another redirect | Code bound to its `redirect_uri` | `sec/test_oauth.py::test_code_is_bound_to_its_redirect_uri` |
| S | Consent CSRF | Consent is a cookie POST with an origin check (10.1) | `sec/test_requests.py::test_oauth_consent_needs_a_trusted_origin` |
| T | Forged JWTs: `alg=none`, HS256 with the public key, unknown `kid` | Algorithm pinned per `kid`; keys only from the server's own store (12.2) | `sec/test_oauth.py::test_hs256_signed_with_the_public_key_is_rejected`, `tests/plugins/oauth_provider/test_security.py::test_forged_tokens_are_rejected` |
| T | Validly signed token with a wrong `typ`, `aud`, `iss`, `exp` or `jti` | Each claim checked; token row must exist and not be revoked (12.2) | `sec/test_oauth.py::test_tampered_tokens_signed_with_the_real_key_are_rejected` |
| R | Disputed grant | Consent rows and `oauth.consent_granted` events (12.2, 14) | `tests/plugins/oauth_provider/test_flow.py::test_consent_page_and_ids` |
| I | Secrets in the database | Codes, refresh tokens and client secrets hashed; private keys AES-GCM (12) | `tests/plugins/oauth_provider/test_flow.py::test_no_secrets_in_the_database`, `sec/test_raw_tokens.py::test_full_scenario_leaves_no_secret_behind` |
| I | SSRF through CIMD `client_id` URLs | https only, public addresses only (any non-public answer refuses), pinned IP, no redirects, 5 KB, 5 s (12.3) | `sec/test_oauth.py::test_cimd_rejects_any_private_answer_in_a_mixed_lookup`, `tests/plugins/oauth_provider/test_security.py::test_cimd_rejects_non_public_addresses`, `test_cimd_rejections`, `test_cimd_timeout_and_errors_are_not_cached` |
| D | Token endpoint flooding | 30 per 60 s (10.2) | `tests/core/test_pipeline.py::test_oauth_rate_limited_format` |
| E | Replayed code or refresh token | Code reuse revokes its tokens; refresh reuse revokes the family (12.2) | `sec/test_limits_and_replay.py::test_a_replayed_code_revokes_what_it_produced`, `test_a_replayed_refresh_token_revokes_the_family` |
| E | Token used at another resource | Audience-bound tokens (RFC 8707) (12.3) | `tests/plugins/oauth_provider/test_security.py::test_userinfo_refuses_tokens_for_other_resources` |

**Residual risk:**
- A remote resource server that checks only the JWT signature accepts a revoked access token until it expires (10 minutes; CONTRACTS 12.2). In-process checks see the revocation at once.
- Users cannot list or revoke their own consents through a built-in endpoint ([Q1-O1-asvs-gaps](../requests/Q1-O1-asvs-gaps.md)).
- The OpenID conformance run is pending ([conformance](conformance/README.md)).

## 5. MCP resource servers (O2, not merged)

**Assets:** MCP tools and the data behind them.
**Boundaries:** an MCP client presenting an O1 token to an MCP server.

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| S | Token issued for another server accepted | Audience check against the server's resource URL (12.4) | O1 side: `tests/plugins/oauth_provider/test_flow.py::test_resources`. The MCP side is pending O2 |
| E | Token passthrough to upstream APIs | Forbidden by the MCP spec; O2 verifies `aud` and never forwards tokens | Pending O2 |
| I | Discovery points clients at a hostile server | RFC 9728 metadata generated from config, not request headers | Pending O2 |

**Residual risk:** everything on the MCP side until O2 merges.

## 6. API keys (P1)

**Assets:** `gak_` keys, the scopes on them.
**Boundaries:** scripts, CI and agents sending `Authorization: Bearer gak_...` or `X-API-Key`.

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| S | Guessing keys | 256-bit random keys, hashed lookup, constant-time compare (12) | `tests/plugins/api_key/test_api_key.py::test_hash_comparison_uses_crypto_equal`, `test_unknown_and_malformed_keys` |
| T | Widening a key's scopes | Scopes limited to `allowed_scopes` (12) | `tests/plugins/api_key/test_api_key.py::test_scope_outside_allowed_is_invalid` |
| I | Key shown again or logged | Shown once; never stored or put in events (12) | `tests/plugins/api_key/test_api_key.py::test_key_is_shown_once_and_never_stored`, `test_events_never_contain_keys` |
| D | One key flooding the app | Per-key rate limit (12) | `tests/plugins/api_key/test_api_key.py::test_per_key_rate_limit` |
| E | Another user's key managed | Owner check on every key endpoint (12) | `tests/plugins/api_key/test_api_key.py::test_other_users_keys_are_not_found` |
| E | Revoked or expired key still works | Checked on every request (12) | `tests/plugins/api_key/test_api_key.py::test_delete_disable_and_expiry_apply_at_once` |

**Residual risk:** a leaked key works until it is revoked or expires. Expiry is optional by default.

## 7. Agents (O3, not merged)

**Assets:** agent principals, their keys and OAuth clients, and the `act` claim.
**Boundaries:** an agent acting for a user or an org.

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| S | An agent acting as the user directly | Tokens carry `act` naming the agent (12.2) | Pending O3 |
| R | Unclear who acted | Sessions and events record the agent (12.2) | Pending O3 |
| E | A disabled agent's credentials still work | Agent row checked on every token and key (12.2) | `tests/plugins/api_key/test_api_key.py::test_agent_keys_carry_the_agent`; O1 checks `agent_id` on tokens. The rest is pending O3 |

**Residual risk:** everything beyond key attribution until O3 merges.

## Modules not merged yet

The tests below are skipped with a reason, and become real tests when the module lands:
- P2: two-factor, `finish_challenge`, TOTP replay
- P3: passkey challenges
- P4: magic link and email OTP enumeration and limits
- P5: invitations
- P6: bans

Each module's merge adds its rows to the tables above.
