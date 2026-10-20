# r/Python (Showcase)

**Rules:** r/Python asks showcase posts for three sections, "What My Project Does",
"Target Audience" and "Comparison", and a Showcase flair. Reddit blocked automated reads
on 2026-10-16, so read the current sidebar and the pinned showcase rules before posting,
including whether showcases are limited to certain days or a weekly thread.

## Title

GotAuth: open-source auth for FastAPI with API keys, agent identities and an OAuth 2.1 server for MCP

## Post

**Source:** https://github.com/gotauth/gotauth (MIT)
**Docs:** https://gotauth.ablacky.com/docs/

### What My Project Does

GotAuth is an auth library that runs inside a FastAPI (or Starlette, or Litestar) app
and keeps everything in your own database through SQLAlchemy:

- sign-up and sign-in with email and password, sessions, and social login
- two-factor, passkeys, magic links, organizations with roles, an admin plugin
- API keys with scopes, and agent identities: an agent owned by a user or an
  organization, with its own keys and OAuth clients, whose tokens carry an `act`
  claim naming it
- an OAuth 2.1 and OpenID provider that MCP clients (Claude, MCP Inspector and others)
  can sign in through, with a one-line integration for FastMCP and one for the MCP SDK

Every route is a real FastAPI route in your OpenAPI schema, and protected routes use
dependencies:

```python
CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]


@app.get("/projects")
async def projects(user: CurrentUser) -> list[str]: ...
```

It also ships `gotauth check`, a scanner for risky hand-written auth that works on any
project: `uvx gotauth check`.

### Target Audience

People building FastAPI or ASGI backends, especially AI backends and MCP servers, who
want users, keys and OAuth in their own database rather than a hosted service. It is
version 0.1: the API may still change before 1.0, and it has one maintainer. It has a
security policy, a threat model and an OWASP ASVS 5.0 level 2 mapping in the repo, but
the OpenID Foundation conformance run for the OAuth server is still to do. Try it on a
new project before an existing production one.

### Comparison

- **fastapi-users:** covers register, login, reset, verify and OAuth login, and is
  widely used. It has been in maintenance mode since October 2025. GotAuth adds
  two-factor, passkeys, organizations, API keys and the OAuth server, and has an
  importer that keeps your users' ids and password hashes.
- **Authlib:** standards building blocks (OAuth client, JOSE, an authorization server
  for Flask and Django). You build the user side yourself. GotAuth is the user side
  plus the server, for FastAPI and ASGI.
- **FastMCP's built-in auth providers:** hand sign-in to a separate identity provider
  (Auth0, WorkOS, Google, Keycloak and others). GotAuth is the identity provider, on
  your own user table.
- **Auth0, Clerk, WorkOS:** hosted, with compliance reports, enterprise SSO and SCIM,
  which GotAuth does not have. Your users live on their servers and pricing is per
  user or per connection.
- **django-allauth:** the choice on Django. GotAuth does not support Django.

The full comparison, with a source link for every cell:
https://github.com/gotauth/gotauth/blob/main/docs/launch/comparison.md
