# gotauth.plugins.oauth_provider

An embeddable OAuth 2.1 authorization server and OpenID Connect provider on your own
users, so MCP clients can sign in to your Python MCP servers. Work package O1.
Targets **MCP authorization 2026-07-28; CIMD per draft-00 as cited, with the stricter
draft-02 checks.**

```python
from gotauth.plugins.oauth_provider import oauth_provider

auth = GotAuth(
    ...,
    plugins=[oauth_provider(resources=["https://mcp.example.com/mcp"], mcp=True)],
)
app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
app.mount("/", auth.well_known())  # RFC 8414 metadata at the host root, last
```

## Endpoints (under `base_path`)

| Endpoint | What |
|---|---|
| `GET /oauth2/authorize` | Authorization code + PKCE (S256 only) |
| `POST /oauth2/consent` | The consent form (built-in page, or your `consent_page`) |
| `GET /oauth2/consent?consent_id=` | For your own `consent_page`: what the request asks for (client name and CIMD host, scopes, resource, `redirect_host`, `loopback_only`); only for the user it was made for |
| `POST /oauth2/token` | `authorization_code`, `refresh_token`, `client_credentials` |
| `POST /oauth2/introspect` | RFC 7662, confidential clients |
| `POST /oauth2/revoke` | RFC 7009 |
| `GET /oauth2/jwks`, `GET /oauth2/userinfo` | Keys and OIDC userinfo |
| `GET /.well-known/openid-configuration` | Discovery; the same document is served at `/.well-known/oauth-authorization-server<base_path>` by `auth.well_known()` |
| `POST /oauth2/register` | RFC 7591, only with `allow_dynamic_registration=True` (public clients). Like a CIMD client, a registered client may later ask for any configured scope (MCP step-up); the user consents per scope |
| `GET /oauth2/grants` | The signed-in user's authorized apps: client, scopes, resources, `created_at`, `last_used_at` |
| `POST /oauth2/grants/revoke` | `{client_id}`: deletes the user's consent and unused codes for that app and revokes its tokens, which stop working at once |

Server-side only (`auth.api.call(...)`): `create_oauth_client`, `list_oauth_clients`,
`get_oauth_client`, `update_oauth_client`, `delete_oauth_client`,
`rotate_oauth_client_secret`, `rotate_signing_key`, `revoke_oauth_tokens`,
`verify_access_token`.

## Rules

- **Issuer** is `base_url + base_path` without a trailing slash; it is the metadata
  `issuer`, the access token `iss` and the `iss` on every redirect back to the client
  (RFC 9207), errors included.
- **Redirect URIs**: `https`, or `http` on `localhost`, `127.0.0.1` or `[::1]`; exact
  match, except that a loopback port may differ. `redirect_uri` is always required. A bad client or redirect URI gets an
  error page, never a redirect.
- **Resources** (RFC 8707): at most one per request, from `resources`; the token `aud`
  is that resource, or the issuer when none was asked for. A token for one MCP server
  is rejected at another. `mcp=True` makes `resource` required.
- **Codes** (`gac_`) live 60 seconds and work once; a replayed code revokes the tokens
  it produced. **Refresh tokens** (`gar_`) rotate on every use; reusing an old one
  revokes the whole family.
- **Access tokens** are JWTs (`typ: at+jwt`, ES256 by default) with `jti` = the grant
  row. In this app they resolve as `Principal(via="oauth_token")`; revocation applies
  on the next request. Remote resource servers that only check the JWT accept a revoked
  token until it expires (10 minutes by default); use O2's `introspect=True` when that
  is too long.
- **Refresh scope narrowing** applies to the new access token only; the grant keeps
  its scopes, so a later refresh can ask for them again.
- **Revoking an access token** (RFC 7009) also revokes its refresh token, as section
  2.1 allows: the grant is over.
- **Userinfo** accepts only tokens for this server (`aud` = issuer or `base_url`); a
  token bound to an MCP resource cannot read the user's profile.
- **ID tokens** carry `auth_time` = when the user signed in (the session's creation),
  kept through refreshes.
- **Consent** is remembered per client, scopes and resource. A CIMD client on a
  loopback redirect always sees the screen again: any local program could claim it.
  The built-in page has no JavaScript and cannot be framed.
- **CIMD**: an https `client_id` with a path is fetched after DNS resolution, from a
  vetted globally routable address only (private, shared, loopback, link-local,
  unique-local, multicast and IPv4-mapped addresses are refused; NAT64 addresses are
  judged by the IPv4 address they embed), with no redirects, a 5 second timeout and a
  5 KB limit. Valid documents are cached within 1 minute to 24 hours; failures are
  never cached.
- **Keys** are created on first use; private keys are stored encrypted. A rotated key
  stays in the JWKS for one access-token lifetime.
- Nothing secret is stored in clear: codes, refresh tokens and client secrets
  (`gcs_`, shown once) are hashed.

## Conformance

`gotauth.plugins.oauth_provider.conformance:create_app` and `conformance/plan.json` set
up a run of the OpenID conformance suite (work package Q1).
