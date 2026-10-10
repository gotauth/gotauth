# OWASP ASVS 5.0 Level 2 mapping

Checked on 2026-10-10 against ASVS **5.0.0**, chapters V6 to V11, every requirement at Level 1 or 2. Level 3 items are left out, except where a test already covers one (noted in the text).

**Status values:**
- **met**
- **partial:** part of the requirement holds; the note says what is missing
- **not met**
- **pending:** owned by a work package that has not merged
- **app:** the host application's responsibility; GotAuth gives the means
- **n.a.:** the feature does not exist in GotAuth

Test paths use `sec/` for `tests/security/`. Open gaps link their request files.

**Summary:**

| Chapter | met | partial | not met | pending | app | n.a. |
|---|---|---|---|---|---|---|
| V6 Authentication | 18 | 1 | 4 | 9 | 0 | 3 |
| V7 Session Management | 9 | 7 | 1 | 0 | 1 | 0 |
| V8 Authorization | 5 | 0 | 0 | 1 | 1 | 0 |
| V9 Self-contained Tokens | 7 | 0 | 0 | 0 | 0 | 0 |
| V10 OAuth and OIDC | 25 | 1 | 1 | 0 | 0 | 2 |
| V11 Cryptography | 12 | 1 | 0 | 0 | 0 | 1 |

## V6 Authentication

| Id | Status | Where | Test or note |
|---|---|---|---|
| 6.1.1 | met | CONTRACTS 10.2; [threat model](threat-model.md) | Rate limits per IP+path and per email, with defaults listed in 10.2 |
| 6.1.2 | not met | C2 | No list of context-specific words. [Q1-C2-asvs-gaps](../requests/Q1-C2-asvs-gaps.md) |
| 6.1.3 | met | [threat model](threat-model.md) sections 1-7 | Each sign-in path and its controls |
| 6.2.1 | met | CONTRACTS 8: min 8, configurable | `tests/email_password/test_flows.py::test_length_boundaries` |
| 6.2.2 | met | `change_password` | `tests/email_password/test_flows.py::test_change_password` |
| 6.2.3 | met | `ChangePasswordIn.current_password` | `tests/email_password/test_flows.py::test_change_password` |
| 6.2.4 | not met | C2 | No check against common passwords. [Q1-C2-asvs-gaps](../requests/Q1-C2-asvs-gaps.md) |
| 6.2.5 | met | C2 checks length only | `tests/email_password/test_flows.py::test_length_boundaries` |
| 6.2.6 | met | `registry/` sign-in and sign-up forms use `type="password"` | D2 component tests |
| 6.2.7 | met | `registry/` forms set `autoComplete` and never block paste | D2 component tests |
| 6.2.8 | met | Passwords are hashed as received; no strip or case change | Imported bcrypt hashes (I1) compare only the first 72 bytes until rehashed at the next sign-in (`tests/email_password/test_flows.py::test_weak_hashes_are_upgraded_after_sign_in`) |
| 6.2.9 | met | Max 128 characters | `tests/email_password/test_flows.py::test_length_boundaries` |
| 6.2.10 | met | No expiry on passwords | n/a |
| 6.2.11 | not met | C2 | See 6.1.2 |
| 6.2.12 | not met | C2 | No breached-password hook. [Q1-C2-asvs-gaps](../requests/Q1-C2-asvs-gaps.md) |
| 6.3.1 | met | CONTRACTS 10.2 | `sec/test_limits_and_replay.py::test_per_email_limits_hold_across_rotating_ips` |
| 6.3.2 | met | No account is created by GotAuth itself | n/a |
| 6.3.3 | pending | P2 (TOTP), P3 (passkeys) | Single factor until they merge |
| 6.3.4 | met | Endpoint tables, CONTRACTS 13.1 and 12.3 | `test_endpoints_match_the_contract_table` in each module's tests |
| 6.4.1 | met | Verification tokens: 256-bit random, 24h, single use | `sec/test_limits_and_replay.py::test_verification_and_reset_tokens_work_once` |
| 6.4.2 | met | No hints or secret questions | n/a |
| 6.4.3 | partial | Reset needs email proof (`test_reset_password_verifies_the_email`) | Not bypassing a second factor is pending P2 |
| 6.4.4 | pending | P2 (backup codes, recovery) | |
| 6.5.1 | pending | P2, P4 | `sec/test_limits_and_replay.py::test_second_factor_and_invitation_replay` (skipped) |
| 6.5.2 | pending | P2 (backup codes) | |
| 6.5.3 | pending | P2, P4 | |
| 6.5.4 | pending | P2, P4 | |
| 6.5.5 | pending | P4: magic links and email OTPs must expire in 10 minutes or less | |
| 6.6.1 | n.a. | No SMS or phone factors | |
| 6.6.2 | pending | P4 | |
| 6.6.3 | pending | P4; the per-email limits in 10.2 already list `/email-otp/send` | `sec/test_limits_and_replay.py::test_per_email_limits_on_magic_link_and_otp` (skipped) |
| 6.8.1 | met | Accounts keyed by `(provider_id, account_id)`; CONTRACTS 11 linking rules | `tests/social/test_flow.py::test_link_social_refuses_a_pair_owned_by_someone_else`, `test_linking_matrix` |
| 6.8.2 | met | ID tokens verified against the provider JWKS | `tests/social/test_providers.py::test_bad_id_tokens_are_rejected` |
| 6.8.3 | n.a. | No SAML (E1 later) | |
| 6.8.4 | n.a. | No authentication-strength requirement on social providers | |

The enumeration test also covers 6.3.8 (Level 3) for bodies, and for timing on sign-in. The reset and verification timing gap is [Q1-C2-timing](../requests/Q1-C2-timing.md).

## V7 Session Management

**Session policy** (what 7.1.1 and 7.1.2 ask to be documented):
- **Inactivity timeout:** `expires_in`, 7 days by default, extended on use once per `update_age` (1 day).
- **Absolute lifetime:** none yet. A session used at least once a week never ends. See [Q1-C3-asvs-gaps](../requests/Q1-C3-asvs-gaps.md).
- **"Remember me" off:** `short_expires_in`, 1 day.
- **Concurrent sessions:** no limit. Users see their sessions with `list_sessions` and end them with `revoke_session` or `revoke_other_sessions`.
- **Cookie cache:** off by default. When on, a revoked session keeps working for at most `cookie_cache.max_age`, 5 minutes and capped at 5.

| Id | Status | Where | Test or note |
|---|---|---|---|
| 7.1.1 | partial | Policy above; CONTRACTS 7 | No absolute lifetime (7.3.2) |
| 7.1.2 | met | Policy above | No limit, by design |
| 7.1.3 | partial | Social login sessions are independent of the provider's session; O1 has no logout endpoint | Documented here only |
| 7.2.1 | met | Every token is checked against the database (or the HMAC cache) | `tests/sessions/test_service.py::test_get_rejects_foreign_prefixes_and_unknown_tokens` |
| 7.2.2 | met | Random per-session tokens | `tests/sessions/test_service.py::test_each_create_makes_a_new_token_even_when_one_is_presented` |
| 7.2.3 | met | 256 bits from `secrets` | `tests/crypto/test_kit.py` |
| 7.2.4 | partial | Sign-in always issues a new token (`sec/test_requests.py::test_a_planted_session_cookie_is_never_adopted`) | The session presented at sign-in is not ended. [Q1-C3-asvs-gaps](../requests/Q1-C3-asvs-gaps.md) |
| 7.3.1 | met | `expires_in`, sliding | `tests/sessions/test_service.py::test_expiry_and_refresh_properties` |
| 7.3.2 | not met | C3 | [Q1-C3-asvs-gaps](../requests/Q1-C3-asvs-gaps.md) |
| 7.4.1 | met | `sign_out` and `revoke_session` delete the row | `tests/email_password/test_flows.py::test_sign_out`, `tests/sessions/test_http.py::test_revoked_bearer_is_unauthenticated` |
| 7.4.2 | partial | Deleting a user ends their sessions (`tests/sessions/test_service.py::test_sessions_of_deleted_users_are_not_returned`) | Disabling (bans) is pending P6 |
| 7.4.3 | met | `change_password(revoke_other_sessions=True)`; reset ends all sessions by default | `tests/email_password/test_flows.py::test_reset_password_revokes_sessions_by_default` |
| 7.4.4 | app | `registry/` UserButton has sign-out | |
| 7.4.5 | partial | `SessionService.revoke_all` runs in-process | No admin endpoint until P6 |
| 7.5.1 | partial | `change_password`, `delete_user` and `unlink_account` need a fresh session | `change_email` does not. [Q1-C2-asvs-gaps](../requests/Q1-C2-asvs-gaps.md) |
| 7.5.2 | partial | `list_sessions`, `revoke_session`, `revoke_other_sessions` | No re-authentication before revoking |
| 7.6.1 | met | GotAuth as an OpenID provider has no single logout; documented here | |
| 7.6.2 | met | Sessions start only from a sign-in request; O1 asks for consent | `tests/plugins/oauth_provider/test_security.py::test_cimd_loopback_always_shows_consent` |

## V8 Authorization

GotAuth decides who the caller is (`Principal`) and what scopes they hold. The host app decides what they may do with its own data.

| Id | Status | Where | Test or note |
|---|---|---|---|
| 8.1.1 | met | Each endpoint's auth mode in CONTRACTS 13.1 and 12.3; scopes in 12.1 | |
| 8.1.2 | app | Field rules for the app's own data | |
| 8.2.1 | met | `auth="session"` endpoints refuse other principals; `require()` in A1 | `tests/core/test_pipeline.py::test_session_endpoint_rejects_api_keys` |
| 8.2.2 | met | Owner checks on sessions and keys | `tests/sessions/test_http.py::test_another_users_session_is_not_found`, `tests/plugins/api_key/test_api_key.py::test_other_users_keys_are_not_found` |
| 8.2.3 | met | `update_user` accepts only `name` and `image` | `tests/email_password/test_flows.py::test_update_user` |
| 8.3.1 | met | All checks run on the server | |
| 8.4.1 | pending | P5 (organizations) | `tests/plugins/api_key/test_api_key.py::test_org_key_with_permission` covers org keys |

## V9 Self-contained Tokens

The self-contained tokens are O1 access and ID tokens, social ID tokens, and the C3 cookie cache (HMAC).

| Id | Status | Where | Test or note |
|---|---|---|---|
| 9.1.1 | met | Signature checked before claims | `sec/test_oauth.py::test_tampered_tokens_signed_with_the_real_key_are_rejected`, `tests/sessions/test_service.py::test_tampered_cache_is_ignored` |
| 9.1.2 | met | Algorithm pinned per `kid` | `sec/test_oauth.py::test_hs256_signed_with_the_public_key_is_rejected` |
| 9.1.3 | met | O1 keys from its own store; social JWKS from the configured issuer | `tests/plugins/oauth_provider/test_security.py::test_forged_tokens_are_rejected` (unknown `kid`) |
| 9.2.1 | met | `exp` against the injected clock; 60 s `iat` leeway | `sec/test_oauth.py::test_tampered_tokens_signed_with_the_real_key_are_rejected` (expired) |
| 9.2.2 | met | `typ: at+jwt` for access tokens | Same test (wrong `typ`); ID tokens refused as access tokens in `test_forged_tokens_are_rejected` |
| 9.2.3 | met | `aud` checked against the resource or local audiences | Same test (other audience); `tests/plugins/oauth_provider/test_security.py::test_userinfo_refuses_tokens_for_other_resources` |
| 9.2.4 | met | Every access token carries `aud` | `tests/plugins/oauth_provider/test_security.py::test_access_token_claims` |

## V10 OAuth and OIDC

GotAuth is an OAuth client (C4, social login), an authorization server and OpenID provider (O1), and an in-process resource server (`verify_access_token`; O2 for MCP).

| Id | Status | Where | Test or note |
|---|---|---|---|
| 10.1.1 | met | Provider tokens not stored by default; GotAuth's own tokens stay in HttpOnly cookies | `tests/social/test_flow.py::test_provider_tokens_are_not_stored_by_default` |
| 10.1.2 | met | `state` bound to a cookie and to the provider | `tests/social/test_flow.py::test_cookie_for_another_state_is_rejected` |
| 10.2.1 | met | PKCE and `state` on every provider | `tests/social/test_flow.py::test_new_user_signs_in_and_pkce_is_checked` |
| 10.2.2 | met | One callback path per provider, and `state` names its provider | `tests/social/test_flow.py::test_state_of_another_provider_is_rejected` |
| 10.3.1 | met | Audience check | `tests/plugins/oauth_provider/test_security.py::test_userinfo_refuses_tokens_for_other_resources` |
| 10.3.2 | met | `verify_access_token(scopes=...)`; `require()` | `tests/plugins/oauth_provider/test_flow.py::test_issued_scopes_stay_within_granted` |
| 10.3.3 | met | User from the token row's `user_id` (`sub`), issuer fixed | |
| 10.3.4 | met | `auth_time` in tokens (CCR 003) for apps that need recentness | `tests/plugins/oauth_provider/test_security.py::test_id_token_auth_time_is_the_sign_in_time` |
| 10.4.1 | met | Exact match; loopback ports per RFC 8252 | `sec/test_oauth.py::test_unregistered_redirects_never_receive_a_redirect` |
| 10.4.2 | met | Single use; reuse revokes the tokens | `sec/test_limits_and_replay.py::test_a_replayed_code_revokes_what_it_produced` |
| 10.4.3 | met | Codes live 60 seconds (also meets the Level 3 limit) | |
| 10.4.4 | met | Per-client `grant_types`; no implicit or password grant | `tests/plugins/oauth_provider/test_flow.py::test_client_credentials` |
| 10.4.5 | met | Rotation with family revocation (not sender-constrained) | `sec/test_limits_and_replay.py::test_a_replayed_refresh_token_revokes_the_family` |
| 10.4.6 | met | S256 required; `plain` refused | `tests/plugins/oauth_provider/test_flow.py::test_pkce_is_required_and_checked` |
| 10.4.7 | met | DCR off by default; metadata validated; consent always shown | `tests/plugins/oauth_provider/test_security.py::test_dynamic_registration` |
| 10.4.8 | met | A rotated refresh token keeps its family's expiry (30 days) | |
| 10.4.9 | partial | `revoke_oauth_tokens` server call | No user-facing endpoint or UI. [Q1-O1-asvs-gaps](../requests/Q1-O1-asvs-gaps.md) |
| 10.4.10 | met | Confidential clients authenticate at token, revoke and introspect | `tests/plugins/oauth_provider/test_flow.py::test_introspection_and_revocation` |
| 10.4.11 | met | Issued scopes stay within the client's and the user's grant | `tests/plugins/oauth_provider/test_flow.py::test_issued_scopes_stay_within_granted` |
| 10.5.1 | met | `nonce` on OIDC providers | `tests/social/test_flow.py::test_oidc_providers_get_a_nonce_without_openid_scope` |
| 10.5.2 | met | Accounts keyed by `sub` | `tests/social/test_providers.py::test_generic_oidc` |
| 10.5.3 | met | `iss` must equal the configured issuer | `tests/social/test_providers.py::test_microsoft_common_checks_the_tenant_issuer` |
| 10.5.4 | met | `aud` must be the client id | `tests/social/test_providers.py::test_bad_id_tokens_are_rejected` |
| 10.5.5 | n.a. | No back-channel logout | |
| 10.6.1 | met | `response_type=code` only | `tests/plugins/oauth_provider/test_flow.py::test_issuer_and_discovery` |
| 10.6.2 | n.a. | No RP-initiated logout | |
| 10.7.1 | met | Consent per client, scopes and resource; CIMD on loopback always asks | `tests/plugins/oauth_provider/test_security.py::test_cimd_loopback_always_shows_consent` |
| 10.7.2 | met | Consent page lists the client, scopes and resource | `tests/plugins/oauth_provider/test_flow.py::test_consent_page_and_ids` |
| 10.7.3 | not met | No way for users to list or revoke consents | [Q1-O1-asvs-gaps](../requests/Q1-O1-asvs-gaps.md) |


## V11 Cryptography

**Cryptographic inventory** (11.1.1, 11.1.2):

| Use | Algorithm | Key or parameters | Rotation |
|---|---|---|---|
| Password hashing | scrypt (default), argon2id (extra), bcrypt (verify only, imports) | scrypt `ln=15, r=8, p=1` | Tagged format; rehash on sign-in when parameters change |
| Token hashing (`gas_`, `gak_`, `gar_`, `gac_`, `gav_`, `gcs_`) | SHA-256 | Tokens are 256-bit random | n/a |
| Cookie and state signing | HMAC-SHA256 | `derive_key("sign:" + purpose)`, HKDF-SHA256 from `secret` | Change `secret`; old cookies stop working |
| Encryption at rest (provider tokens, JWK private keys) | AES-256-GCM, `v1.` format | `derive_key("encrypt")`, HKDF-SHA256 from `secret`; the purpose is the associated data | Versioned ciphertext |
| JWT signing (O1) | ES256 (default) or RS256 | P-256, or RSA 2048 | `rotate_signing_key`; old keys stay published until their tokens expire |
| Random values | `secrets` (OS CSPRNG) | | |
| TOTP (P2, pending) | HMAC-SHA1 per RFC 6238 | | |

**Key lifecycle:** `secret` comes from the app's environment (`gotauth secret` makes one). Every other key derives from it, or is encrypted under a key derived from it. Signing keys rotate through `rotate_signing_key` (`POST /oauth2/keys/rotate`, server only). Changing `secret` ends all cookie caches and makes stored encrypted values unreadable.

| Id | Status | Where | Test or note |
|---|---|---|---|
| 11.1.1 | met | Key lifecycle above | |
| 11.1.2 | met | Inventory above | |
| 11.2.1 | met | `cryptography`, `hashlib`, `hmac`, `secrets`, PyJWT | |
| 11.2.2 | met | Tagged password hashes, `kid` on JWTs, versioned ciphertext | `tests/plugins/oauth_provider/test_security.py::test_key_rotation_keeps_old_tokens_valid_until_expiry` |
| 11.2.3 | met | 256-bit tokens, AES-256, P-256, RSA 2048 | |
| 11.3.1 | met | GCM only; no RSA encryption | |
| 11.3.2 | met | AES-GCM | `tests/crypto/test_kit.py` |
| 11.3.3 | met | GCM with the purpose as associated data | `tests/crypto/test_kit.py` |
| 11.4.1 | met | SHA-256 everywhere; SHA-1 only inside HMAC for TOTP (P2), as RFC 6238 requires | |
| 11.4.2 | partial | scrypt, but `ln=15, r=8, p=1` is below OWASP's minimum (`ln=17, r=8, p=1` or equivalent) | [Q1-F3-scrypt-cost](../requests/Q1-F3-scrypt-cost.md) |
| 11.4.3 | met | SHA-256 for signatures and token hashes | |
| 11.4.4 | n.a. | No keys derived from passwords | |
| 11.5.1 | met | `secrets`; 256 bits | `tests/crypto/test_kit.py` |
| 11.6.1 | met | ES256 or RS256 with RSA 2048 | |
