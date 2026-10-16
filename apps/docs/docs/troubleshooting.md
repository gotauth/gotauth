# Troubleshooting

## Errors

Every error is JSON: `{"error": {"code": "...", "message": "...", "details": ...}}`.
OAuth endpoints answer in the RFC 6749 shape instead (`{"error", "error_description"}`).

| Code | Status | Usually means |
|---|---|---|
| `INVALID_REQUEST` | 400 | The body or query does not match the endpoint. The message never repeats what you sent |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | A JSON endpoint called without `Content-Type: application/json` (or a form endpoint without a form) |
| `INVALID_CREDENTIALS` | 401 | Wrong email or password, the same answer for both |
| `UNAUTHENTICATED` | 401 | No credential, or an expired or revoked one |
| `FORBIDDEN` | 403 | Signed in, but not allowed |
| `INSUFFICIENT_SCOPE` | 403 | The key or token lacks a scope; `details.required` lists it |
| `FRESH_SESSION_REQUIRED` | 403 | A sensitive action with a session older than `sessions.fresh_age`: sign in again |
| `EMAIL_NOT_VERIFIED` | 403 | Sign-in before the email was verified |
| `ORIGIN_NOT_ALLOWED` | 403 | A cookie-authenticated change from an origin that is not `base_url` or in `trusted_origins` |
| `USER_ALREADY_EXISTS` | 409 | Only with email verification off |
| `TOKEN_INVALID`, `TOKEN_EXPIRED` | 400 | A verification or reset link (or a sign-in step) that was used, changed or is too old. Invitations answer `ORG_INVITATION_INVALID` instead |
| `RATE_LIMITED` | 429 | Too many attempts; `Retry-After` says when to retry |
| `INTERNAL_ERROR` | 500 | An unexpected error; the server log has it |

Plugins add their own codes, prefixed with their name (`API_KEY_INVALID`,
`TWO_FACTOR_INVALID_CODE`, `ORG_FORBIDDEN`, ...): each plugin page lists them.

## `ORIGIN_NOT_ALLOWED`

A browser app on another origin than `base_url` (for example a Vite dev server on
`localhost:5173` calling an API on `localhost:8000`) must be listed:

<!-- sample: skip: a configuration fragment -->
```python
auth = GotAuth(..., base_url="http://localhost:8000", trusted_origins=["http://localhost:5173"])
```

Simpler still: proxy `/api` through the frontend's dev server, so the browser sees one
origin (`examples/fastapi-nextjs` does this with a Next.js rewrite).

## The session cookie is not kept

- **On https:** the cookie is named `__Secure-gotauth.session_token` and is `Secure`.
  If `base_url` says https but the browser reaches the app over http, the browser drops
  it. Make `base_url` the address users actually use.
- **On another domain:** cookies are `SameSite=Lax` and belong to the host of the
  response. A frontend on another site can't use them; proxy the API through the
  frontend's domain, or use bearer sessions for native clients.
- **Behind a proxy:** rate limits see the proxy's IP until you set `trusted_proxies`
  and `ip_headers` ([Security](security.md#behind-a-proxy)).

## Emails

- **On localhost** with no `email_sender`, GotAuth prints every email, link included,
  to the console (stderr). Elsewhere, it refuses to start without a sender: see
  [Email delivery](modules/email.md).
- **In tests**, use `email_sender=fake_mailer()` (or `make_auth(mailer=...)`) and read
  `mailer.last(kind, to)`.
- **Events are always delivered in the background,** and emails too off localhost, so
  responses don't wait. In tests and scripts, `await auth.drain()` before checking them.

## `ConfigError` at start

GotAuth checks its configuration when it is built and refuses unsafe setups: a secret
shorter than 32 characters, an email feature without a sender off localhost, a plugin
missing another it needs, or two plugins with the same route. The message names the
setting.
