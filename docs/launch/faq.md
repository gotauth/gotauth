# Security FAQ

Answers to the questions launch threads will ask. Each answer points to where the
behavior is specified or tested, so replies can link to it. For the docs site, the same
answers can go on the security page.

## Where does my data live?

In your database, through the adapter you pass (`sqlalchemy_adapter` for Postgres or
SQLite, or the in-memory adapter for tests). GotAuth runs inside your app and calls no
GotAuth service; there is none. The only outside calls are the ones you configure:
social login providers, your email sender, and CIMD documents of OAuth clients.

**Tables** are named with a prefix, `auth_` by default (`auth_user`, `auth_session`,
...), so they sit next to a `user` table your app already has. Change it with
`advanced={"table_prefix": "..."}`. `gotauth generate` writes Alembic revisions for
them; `gotauth migrate` creates them directly. Optional secondary storage (Redis, or
your own) holds counters and caches, such as rate-limit windows and cached sessions.

## What is hashed or encrypted at rest?

- **Hashed (SHA-256):** session tokens, API keys, email verification and reset tokens,
  magic links, invitation tokens, OAuth authorization codes, refresh tokens and client
  secrets. Each is shown once, to its owner. One-time codes (two-factor email codes,
  backup codes) are hashed too.
- **Passwords:** scrypt by default (N=2^15, r=8, p=3, the OWASP minimum at 32 MiB), or
  argon2id with the `argon2` extra. Hashes from fastapi-users (bcrypt, argon2) keep
  working and are rehashed at the next sign-in.
- **Encrypted (AES-GCM):** TOTP secrets, the OAuth server's private signing keys, and
  social provider tokens when you choose to store them (they are not stored by
  default).
- **Tested:** a security test runs a full scenario on SQLite (sign-up, sessions, API
  keys, OAuth, two-factor, magic links, invitations) and scans every table and every
  log line for a raw secret.

Sources: `docs/security/threat-model.md`, `tests/security/test_raw_tokens.py`.

## Can someone find out whether an email has an account?

Not from the responses or their timing, with one documented exception.
- Password reset, verification emails, magic links and email codes always answer the
  same body.
- Sign-in for an unknown email checks a dummy password hash and answers
  `INVALID_CREDENTIALS`, like a wrong password.
- Account-only work, such as sending the email, happens after the reply, for every
  address alike.
- **The exception:** sign-up with email verification turned off signs the new user in
  at once, so it has to say when the email is taken (`USER_ALREADY_EXISTS`). With
  verification on (the default), an existing email gets the same "verification sent"
  answer, and the owner gets an email instead.

Sources: CONTRACTS 9.1, `tests/security/test_enumeration.py` (including timing tests).

## How are CSRF and cross-site requests handled?

- A POST, PATCH or DELETE authenticated by a cookie must carry an `Origin` (or
  `Referer`) that matches `base_url` or one of your `trusted_origins`. Otherwise the
  answer is `ORIGIN_NOT_ALLOWED`.
- JSON endpoints require `Content-Type: application/json`, which a browser can't send
  cross-site without a CORS preflight. That also closes login CSRF on endpoints that
  take no cookie.
- Requests with a bearer token or API key don't need an `Origin`; a browser never adds
  those on its own.
- Redirect parameters (`callback_url` and others) must be relative paths or URLs on a
  trusted origin.
- Session cookies are HttpOnly, Secure (except on localhost) and SameSite=Lax.

Sources: CONTRACTS 10.1, `tests/security/test_requests.py`.

## What are the rate limits?

On by default, kept in memory (or in the database, or secondary storage when you run
several processes):

| Paths | Limit |
|---|---|
| Every endpoint | 100 per minute per IP and path |
| Sign-in, sign-up, password reset, verification, two-factor, magic links, email codes | 5 per minute per IP and path |
| Sign-in, password reset, magic link and email code sends | also 10 per 15 minutes per email, across IPs |
| Passkeys | 10 per minute |
| `/oauth2/token` | 30 per minute |

A client IP comes from forwarding headers only when the request arrives from a proxy
you list in `trusted_proxies`.

Sources: CONTRACTS 10.2, `tests/security/test_limits_and_replay.py`.

## How fast does revocation apply?

| What is revoked | Where it is checked | When it applies |
|---|---|---|
| A session | GotAuth, any request | On the next request. With the optional cookie cache, within its `max_age` (5 minutes by default) |
| An API key | GotAuth, any request | On the next request |
| An OAuth token or a client's access ("Connected apps") | In the same process (your API, or an MCP server using `fastmcp_auth(auth, ...)`) | On the next call (a cache of up to 5 seconds is allowed) |
| The same | A remote MCP server that only checks the JWT | When the token expires: 10 minutes by default (`access_token_ttl`) |
| The same | A remote MCP server with introspection on | Within 5 seconds |
| A banned user (admin plugin) | Everywhere above, including `verify_access_token`, introspection and the refresh grant | As for the credential |

Sources: CONTRACTS 12.2, `src/gotauth/integrations/mcp/README.md`,
`tests/security/test_bans.py`.

## What does the OAuth server cover, and what not?

- **Covered:** OAuth 2.1 authorization code with PKCE (required, S256), refresh token
  rotation with reuse detection, client credentials, OpenID Connect (ID tokens,
  userinfo, discovery), RFC 8414 metadata, JWKS with key rotation, introspection (RFC
  7662), revocation (RFC 7009), resource indicators and audience-bound tokens (RFC
  8707), client ID metadata documents and optional dynamic registration (RFC 7591), and
  RFC 9728 metadata for MCP servers. Targets MCP authorization revision 2026-07-28.
- **Not covered:** the implicit and password grants (OAuth 2.1 drops them), token
  exchange (RFC 8693, planned for sub-agents), SAML, SCIM, device flow.
- **CIMD fetches** go only to public addresses, after DNS resolution, with no
  redirects, a 5 second timeout and a 5 KB limit.

Source: `src/gotauth/plugins/oauth_provider/README.md`.

## Has it been audited? What about conformance?

No external audit yet. What exists:
- a threat model (STRIDE, with the test for each threat): `docs/security/threat-model.md`
- an OWASP ASVS 5.0 Level 2 mapping for chapters V6 to V11: `docs/security/asvs.md`
- a security test suite (`tests/security`): enumeration and timing, origin and CSRF,
  redirects, session fixation, cookie flags, raw-secret scan, rate limits, replay of
  every one-time secret, OAuth attacks, bans, and fuzzing of every endpoint
- a review checklist for security-relevant changes

**Not done yet:** the OpenID Foundation conformance run for the OAuth server.

## How do I report a vulnerability?

Privately, through GitHub's private vulnerability reporting: the repository's Security
tab, "Report a vulnerability". Not in a public issue. Targets: acknowledgement within 3
business days, triage within 7 days, a fix within 30 days for critical and high
severity. Fixes ship as a patch release with a GitHub security advisory. Details:
`SECURITY.md`.

## Is it maintained? Who runs it?

One maintainer today, and the security policy says so. GotAuth is pre-1.0: security
fixes go into the latest 0.x release. The roadmap is public in `docs/build-plan.md`.
Token exchange for sub-agents, enterprise SSO and SCIM, and a Flask adapter come later,
when users ask for them. Django is out of scope: django-allauth serves it well.
