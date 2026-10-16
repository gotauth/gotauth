# Security

What GotAuth does by default, the trade-offs you choose, and where the details are.

## Defaults

- **Fail closed.** An unexpected error in any check is a 500 that grants nothing; an
  unknown credential is a 401.
- **Nothing secret at rest.** Session tokens, API keys, OAuth codes and tokens,
  verification links and backup codes are stored as hashes. TOTP secrets and stored
  provider tokens are encrypted. Passwords use scrypt (or argon2id with the `argon2`
  extra), and old hashes are upgraded at the next sign-in.
- **No account enumeration.** With email verification on (the default), sign-up,
  password reset and magic links answer the same, in the same time, whether an account
  exists or not.
- **CSRF protection.** Cookie-authenticated `POST`, `PATCH` and `DELETE` requests must
  send an `Origin` from `base_url` or `trusted_origins`. Cookies are `HttpOnly` and
  `SameSite=Lax`, with the `__Secure-` prefix on https.
- **Rate limits** on sign-in, sign-up, password reset, two-factor and the OAuth
  endpoints, per IP and per account.
- **Fresh sessions** for sensitive changes: password, email, account deletion,
  two-factor, passkeys, agents.
- **OAuth 2.1** with PKCE (S256 only), exact redirect URIs, single-use codes, rotating
  refresh tokens with reuse detection, and audience-bound tokens.

## Trade-offs you choose

!!! warning "The cookie cache delays revocation"
    With `sessions={"cookie_cache": {"enabled": True}}`, a revoked session keeps working
    in a browser that holds a cached copy, for up to `cookie_cache.max_age` (5 minutes
    by default). See [Sessions](concepts/sessions.md#the-cookie-cache).

!!! warning "Without email verification, sign-up reveals existing accounts"
    With `email_password={"require_email_verification": False}`, signing up with a
    taken email must answer `USER_ALREADY_EXISTS`, which tells anyone the address has
    an account. Keep verification on if that matters.

!!! warning "Remote resource servers accept a revoked token until it expires"
    A resource server in another process that checks GotAuth's JWT access tokens by
    signature alone accepts a revoked token until it expires (10 minutes by default).
    Use `introspect=True` where that is too long: see [MCP servers](guides/mcp.md).

## Behind a proxy

GotAuth reads the client IP (for rate limits and session details) from the connection.
Behind a reverse proxy, set both:

<!-- sample: skip: a configuration fragment -->
```python
auth = GotAuth(..., advanced={"trusted_proxies": ("10.0.0.0/8",), "ip_headers": ("x-forwarded-for",)})
```

The header is read only when the connection comes from a trusted proxy, so clients
can't forge their IP.

## Reporting

Report vulnerabilities privately through GitHub's private vulnerability reporting
(the repository's **Security** tab), not in public issues. The
[security policy](https://github.com/gotauth/gotauth/blob/main/SECURITY.md) has the
process and timelines.

## Details

- [Threat model](https://github.com/gotauth/gotauth/blob/main/docs/security/threat-model.md)
- [OWASP ASVS 5.0 Level 2 mapping](https://github.com/gotauth/gotauth/blob/main/docs/security/asvs.md)
- [Review checklist](https://github.com/gotauth/gotauth/blob/main/docs/security/review-checklist.md)
- Releases are published to PyPI with trusted publishing and attestations.
