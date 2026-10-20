# r/mcp

**Rules:** read the sidebar and pinned posts on the day (Reddit blocked automated reads
on 2026-10-16, so they are not checked here). Use the subreddit's project or showcase
flair if it has one.

## Title

An OAuth 2.1 server for Python MCP servers that uses your own user table (open source, CIMD, RFC 8707)

## Post

If you run a Python MCP server for real users, you need an authorization server. The
usual answers are a hosted identity provider (Auth0, WorkOS, Clerk) or Keycloak. I
wanted the users to stay in my app's own database, so I built that part into a
library: GotAuth.

**What it does for an MCP server:**

- `oauth_provider(mcp=True, resources=[...])` turns a FastAPI app into the authorization
  server: authorization code with PKCE (required), refresh token rotation, consent
  pages, JWKS with key rotation, RFC 8414 and OpenID discovery.
- **Client registration:** client ID metadata documents (CIMD), which the 2026-07-28
  spec revision prefers, plus optional dynamic registration (RFC 7591) for clients that
  still use it.
- **Audience-bound tokens** (RFC 8707): a token for one MCP server is refused by
  another.
- **FastMCP:** `FastMCP("projects", auth=fastmcp_auth(auth, resource=URL, scopes=[...]))`.
  The 401 points clients at the RFC 9728 document, a missing tool scope is a 403
  `insufficient_scope` so the client can step up, and tools get the caller from
  `current_access()`.
- **The MCP SDK** (`mcp`): `mcp_sdk_auth(...)` gives the `AuthSettings` and a token
  verifier.
- **Revocation:** the user revokes a client on a "Connected apps" page. An MCP server
  in the same process sees it on the next call. A remote one sees it within 5 seconds
  with introspection on, or when the token expires (10 minutes by default) without it.
- **Agents:** an agent can own API keys and OAuth clients, and its tokens carry an
  `act` claim naming it, so your tools can tell "Ada" from "Ada's agent".

The CIMD fetcher only connects to public addresses (private, loopback, link-local and
similar ranges are refused after DNS resolution), with no redirects, a 5 second
timeout and a 5 KB limit.

**Example:** `examples/fastmcp-server` in the repo runs the whole flow with MCP
Inspector, or with Claude as a custom connector through a tunnel. Its README has a
step-by-step script.

**Not done yet:** the OpenID Foundation conformance run, token exchange (RFC 8693) for
sub-agents, enterprise SSO. It is 0.1 with one maintainer.

Repo: https://github.com/gotauth/gotauth
Docs: https://gotauth.ablacky.com/docs/

I'd like to hear from anyone who has wired auth into a Python MCP server: what did you
end up using, and what was missing?
