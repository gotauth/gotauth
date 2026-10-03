# C4: Social login (OAuth 2 / OIDC client and providers)

| | |
|---|---|
| Lane / wave | Core / **Wave 1** |
| Size | M-L (2-3 agent-days) |
| Depends on | M0 |
| Can start | after M0 |
| Write scope | `src/gotauth/social/**`, `tests/social/`, `changes/C4.*.md` |
| Allowed new deps | none at runtime (httpx and PyJWT are core); dev: respx (already in F1's dev group) |

## Goal
Sign-in and account linking with GitHub, Google, Microsoft, Discord, GitLab, Apple and any OIDC provider, per CONTRACTS section 11: state bound to the browser and the database, PKCE everywhere, verified ID tokens and strict linking rules.

## Build
- Entry point (13.2): `social_plugin() -> Plugin` (id `social`, installed by C1 when providers are given); providers come from `ctx.auth.providers`. Factories exported from `gotauth.social`: `github`, `google`, `microsoft(tenant="common")`, `discord`, `gitlab(base_url="https://gitlab.com")`, `generic_oidc(id, discovery_url)`, `apple` (cut list item 1). All take `client_id`, `client_secret`, `scopes=()`, `store_provider_tokens=False`; each provider sets `callback_method` ("POST" only for Apple). Provider code lives in `social/providers/_<name>.py` so no submodule shadows a factory name.
- Endpoints (13.1):
  - `sign_in_social` POST `/sign-in/social` `{provider, callback_url?, error_callback_url?, scopes?, remember_me=true}` -> RedirectOut.
  - `social_callback` GET `/callback/{provider}` (query `code`, `state`, or `error`).
  - `social_callback_post` POST `/callback/{provider}`, `input_format="form"`, only for providers with `callback_method="POST"` (else NOT_FOUND). Apple's form_post is a cross-site POST that does not carry the Lax state cookie, so it 302s to the GET callback with `code`, `state`, `error` and Apple's first-sign-in `user` field; the GET then runs the normal checks.
  - `link_social` POST `/link-social` (session) `{provider, callback_url?, scopes?}` -> RedirectOut.
  - `list_accounts` GET `/accounts` (session) -> AccountListOut (`id`, `provider_id`, `account_id`, `scope`, `created_at`).
  - `unlink_account` POST `/unlink-account` (session, fresh) `{provider_id, account_id?}`: the user's only sign-in method -> LAST_SIGN_IN_METHOD (when `"passkey"` is in `ctx.auth.plugin_ids`, count `passkey` rows too); emit `account.unlinked`.
- Start: `state = crypto.random_token()`, PKCE verifier `crypto.random_token()`, challenge `crypto.pkce_s256(verifier)`, nonce for OIDC. `verification` row: identifier `oauth_state:<provider>`, `value_hash = hash_token(state)`, 10 minutes, `data` = `crypto.encrypt(JSON {verifier, nonce, callback_url, error_callback_url, link_user_id, remember_me}, purpose="oauth_state")`. Cookie `gotauth.oauth_state` (name via `cookie_name`, so `__Secure-` on https) = `crypto.sign(state, purpose="oauth_state")`, SameSite=Lax, 10 minutes. `redirect_uri` = `base_url + base_path + "/callback/<provider>"`. URLs checked with `gotauth.core.validate_redirect` (local stub with `# TODO(C1)` until C1 merges).
- Callback (a GET that writes, allowed as an OAuth redirect callback): unsign the cookie, `crypto.equal` with `state`, consume the row once (`delete(...) == 1`), clear the cookie, exchange the code with the verifier, fetch the user. Missing or mismatched state -> TOKEN_INVALID; expired -> TOKEN_EXPIRED; provider failures -> PROVIDER_ERROR. Errors redirect to `error_callback_url` (or `callback_url`) with `?error=<CODE>` when given, else JSON.
- Linking exactly as section 11. `link_social`: pair owned by another user -> ACCOUNT_NOT_LINKED; different email -> ACCOUNT_NOT_LINKED unless `allow_different_emails`. A UniqueViolation on `(provider_id, account_id)` from a concurrent callback is retried as "existing pair". Sign-in via `ctx.auth.complete_sign_in(ctx, user, method="social", remember_me=...)`; ChallengeOut -> redirect to `callback_url` with `?challenge=<type>`. Events `user.created`, `account.linked`.
- Provider tokens: only with `store_provider_tokens`, into `access_token_enc` / `refresh_token_enc` / `id_token_enc` via `crypto.encrypt(..., purpose="account_token")`, plus `access_token_expires_at`, `scope`.
- ID tokens in `social/oidc.py`, reusable by E1: PyJWT; JWKS fetched with `ctx.auth.http` (not PyJWKClient, which does blocking I/O), cached 1 hour, refetched once on an unknown `kid`; algorithm allow-list from the provider (no `none`, no HS*); check `iss`, `aud`, `exp` (60s leeway), `nonce`.
- Providers: github (`read:user user:email`; email from `GET /user/emails`, primary and verified only); google (discovery, `email_verified`); microsoft (`tid`-based `iss` check for `common` / `organizations`; email treated as unverified unless a claim proves it); discord (`identify email`, `verified`); gitlab (self-hosted `base_url`); apple (`response_mode=form_post`, name only on first sign-in); generic_oidc (cached discovery).
- New users are created only through `ctx.auth.create_user_record(ctx, data)` (CONTRACTS 13), so user database hooks run and `user.created` is emitted.

## Acceptance tests
- Full flow with `fake_oauth_provider` and `make_context`: new user, existing pair, link_social, ChallengeOut redirect; `complete_sign_in` called with `method="social"`.
- Linking matrix: Hypothesis over (provider verified, local verified, trusted provider, same email) matches section 11 exactly.
- Each real provider: token, user info, `/user/emails` and JWKS responses mocked with `httpx.MockTransport` or respx; ID token signed with a test key; wrong `iss`, `aud`, `nonce`, expired, `alg: none` -> PROVIDER_ERROR.
- Login CSRF: missing cookie, cookie for another state, reused state -> rejected, no session.
- Apple: form POST callback -> 302 to the GET callback -> session; `social_callback_post` for a GET provider -> NOT_FOUND.
- PKCE: the fake provider confirms the verifier matches the challenge.
- Open redirect: `callback_url` on an untrusted origin -> INVALID_REQUEST at `sign_in_social`.
- Without the flag no provider token is stored; with it only ciphertext is.
- LAST_SIGN_IN_METHOD; endpoint objects match `CORE_ENDPOINTS` for the C4 rows.

## Out of scope
- Pipeline, form parsing and redirect validation (C1); sessions (C3); enterprise SSO (E1); OAuth server (O1).

## Notes
- If time runs short, the Apple provider goes first (cut list item 1). `social_callback_post` stays registered (it is in 13.1) and answers NOT_FOUND while no provider uses POST.
- Provider APIs change: check each provider's current docs and record the dates in the README.
