# gotauth.social

Social sign-in and account linking with OAuth 2 and OpenID Connect providers. Work
package C4. `GotAuth` installs `social_plugin()` when `social_providers` is not empty.

```python
from gotauth.social import github, google

auth = GotAuth(..., social_providers=[github(client_id=..., client_secret=...),
                                      google(client_id=..., client_secret=...)])
```

## Providers

| Factory | Protocol | Email verified when | Docs checked |
|---|---|---|---|
| `github()` | OAuth 2 | primary address from `GET /user/emails` is verified | 2026-10-07 |
| `google()` | OIDC (discovery) | `email_verified` claim | 2026-10-07 |
| `microsoft(tenant="common")` | OIDC v2 | `xms_edov` claim only | 2026-10-07 |
| `discord()` | OAuth 2 | `verified` is true | 2026-10-07 |
| `gitlab(base_url=...)` | OIDC (discovery), self-hosted too | `email_verified` claim | 2026-10-07 |
| `apple()` | OIDC, `response_mode=form_post` | `email_verified` claim (sent as a string) | 2026-10-07 |
| `generic_oidc(id, discovery_url)` | OIDC (discovery) | `email_verified` claim | |

Every factory takes `client_id`, `client_secret`, `scopes=()` (replaces the defaults)
and `store_provider_tokens=False`. Apple's `client_secret` is the signed client-secret
JWT Apple requires; generating it is up to the app.

For Microsoft `common`, `organizations` and `consumers`, the ID token issuer must match
the token's own tenant (`tid`).

## Flow

1. `POST /sign-in/social {provider, callback_url?, error_callback_url?}` stores the
   state (hashed) with the PKCE verifier and nonce (encrypted), sets a signed
   `oauth_state` cookie for 10 minutes and returns `{"url": ...}`.
2. The provider redirects to `GET /callback/<provider>`. The state must match the
   cookie and the database; it is consumed once and the cookie is cleared.
3. The code is exchanged with the PKCE verifier, the user is fetched (OIDC: the ID
   token is verified), then the user is signed in through `auth.complete_sign_in` or
   the account is linked.
4. The browser goes to `callback_url` (default `/`), with `?challenge=<type>` when a
   further sign-in step is needed, or to `error_callback_url` with `?error=<CODE>`.

Apple posts the callback cross-site, so the browser does not send the Lax state cookie.
`POST /callback/apple` therefore redirects to the GET callback, where the cookie is
present and every check runs.

## Linking rules (CONTRACTS 11)

- A known `(provider, account id)` signs in its user.
- Otherwise, a user with the same email is linked only when the provider says the
  email is verified **and** the local email is verified or the provider is in
  `account_linking.trusted_providers`. Otherwise `ACCOUNT_NOT_LINKED`.
- Otherwise a new user is created with the provider's verification flag.

When a trusted provider links to a local account whose email was never verified, that
account's password is removed and its sessions are revoked: whoever set the password
never proved the address (pre-account hijacking). The owner can set a new one with a
password reset.

`POST /link-social` links a provider to the signed-in user (same email unless
`allow_different_emails`). `POST /unlink-account` refuses to remove the last sign-in
method.

## ID tokens

`gotauth.social.oidc` verifies ID tokens with PyJWT: the JWKS is fetched with
`auth.http`, cached for an hour and refetched (at most once a minute) for an unknown
key id. Only asymmetric algorithms are accepted (never `none` or HS*). `iss`, `aud`,
`exp` (60 seconds of leeway), `iat`, `sub` and `nonce` are checked. Enterprise SSO (E1)
reuses this module.

## Provider tokens

Not stored by default. With `store_provider_tokens=True` the access, refresh and ID
tokens are stored encrypted (AES-GCM, purpose `account_token`).
