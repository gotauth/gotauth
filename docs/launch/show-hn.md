# Show HN

**Rules checked:** https://news.ycombinator.com/showhn.html on 2026-10-16. Show HN is
for things people can try; no sign-up wall; no landing pages; do not ask anyone to
upvote or comment. Post the GitHub repository, not the landing page.

## Title

Show HN: GotAuth - login for your Python MCP server from your own user table

## URL

https://github.com/gotauth/gotauth

## Text

(Leave the text field empty and post the first comment below right after submitting, or
paste it as the text. Hacker News shows either.)

## First comment

I built GotAuth, an open-source (MIT) auth library for FastAPI and other ASGI apps. The
part I'd like feedback on is the OAuth 2.1 authorization server it includes for MCP
servers.

The problem: an MCP server that real users connect to (from Claude, MCP Inspector or
any other client) needs an OAuth authorization server. The MCP Python SDK's docs say of
that server: "You don't write this. It's your identity provider." FastMCP's built-in
providers all hand sign-in to a separate identity provider. If your users already live
in your own Postgres table and your app is FastAPI, the embeddable options I found were
Django-only (django-allauth) or did not support client ID metadata documents yet.

What GotAuth does:

- Runs inside your app, on your database (SQLAlchemy, Postgres or SQLite). Its tables
  are prefixed `auth_`, so they sit next to an existing `user` table.
- Users, sessions, email and password, social login, two-factor, passkeys,
  organizations, API keys and agent identities.
- An OAuth 2.1 server for MCP clients: authorization code with PKCE, resource
  indicators (tokens are bound to one MCP server), refresh rotation, client ID
  metadata documents (CIMD) and optional dynamic registration, RFC 9728 protected
  resource metadata.
- One line to protect a FastMCP server: `auth=fastmcp_auth(auth, resource=..., scopes=[...])`.
  Tools read the caller with `current_access()`.
- A "Connected apps" page where a user revokes an MCP client. In the same process the
  next call is a 401.

Try it in two minutes (needs uv):

    git clone https://github.com/gotauth/gotauth
    cd gotauth/examples/fastmcp-server
    uv sync --locked
    echo "GOTAUTH_SECRET=$(uv run gotauth secret)" > .env
    set -a && . ./.env && set +a
    uv run gotauth migrate --auth app.auth:auth
    uv run uvicorn app.main:app --port 8000

Then run `npx @modelcontextprotocol/inspector`, connect to http://localhost:8000/mcp
with the client id the app printed, sign up, consent and call `list_projects`.

Or scan your own project for risky hand-written auth (passlib, python-jose, `verify=False`,
HS256 with a literal secret and 9 more rules). It reads files with `ast` only, needs no
extras and makes no network calls:

    uvx gotauth check

What is not done yet:

- It is 0.1, pre-1.0, with one maintainer. The security policy is in SECURITY.md.
- The OpenID Foundation conformance run for the OAuth server has not been done.
- No enterprise SSO (SAML, SCIM) and no token exchange for sub-agents yet.
- FastAPI, Starlette and Litestar only; no Flask or Django adapter.

Why I built it: in a February 2026 benchmark of coding agents, Python auth came out
"100% Custom/DIY: JWT + passlib + python-jose", even though FastAPI's own docs moved
off python-jose in 2024 and off passlib in 2025. I wanted a library an agent can add
in a few lines instead.

Happy to answer anything about the design: hashed tokens, the CIMD fetcher's network
rules, or how revocation reaches a remote MCP server.
