# MCP servers

Let MCP clients (Claude, MCP Inspector, IDE agents) sign your users in to your Python MCP
server, with your own user table. GotAuth plays both roles MCP authorization needs:

- **The authorization server:** `oauth_provider(mcp=True)` issues access tokens after
  the user signs in and consents (OAuth 2.1 with PKCE, client ID metadata documents,
  optional dynamic registration).
- **The resource server guard:** `fastmcp_auth` (FastMCP) or `mcp_sdk_auth` (the MCP
  Python SDK) accepts only GotAuth tokens issued for your server, and answers 401 and
  403 the way MCP clients expect.

Targets MCP authorization revision 2026-07-28. Install with
`pip install "gotauth[fastapi,mcp,sqlalchemy,postgres]"`.

## The authorization server

<!-- sample: skip: a configuration fragment; examples/fastmcp-server runs it -->
```python
from gotauth.plugins.oauth_provider import oauth_provider

RESOURCE = "https://api.example.com/mcp"

auth = GotAuth(
    ...,
    base_url="https://api.example.com",
    plugins=[
        oauth_provider(
            mcp=True,
            resources=[RESOURCE],
            scopes=["openid", "profile", "email", "projects:read", "projects:write"],
            login_page="/sign-in",
        )
    ],
)
app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
app.mount("/", auth.well_known())  # RFC 8414 metadata at the host root, last
```

- `mcp=True` requires an `https` `base_url` (localhost is allowed for development) and
  a `resource` on every request.
- `login_page` is your sign-in page. GotAuth sends the browser there with a
  `callback_url` back to the authorization request.
- The consent page is built in. To use your own, set `consent_page`. It gets
  `?consent_id=...`; read the request with `GET /oauth2/consent?consent_id=...`, or use
  the registry's `ConsentScreen`.

## The MCP server (FastMCP)

<!-- sample: skip: needs fastmcp and a running authorization server -->
```python
from fastmcp import FastMCP
from fastmcp.server.auth import require_scopes

from gotauth.integrations.mcp import current_access, fastmcp_auth

mcp = FastMCP("projects", auth=fastmcp_auth(auth, resource=RESOURCE, scopes=["projects:read"]))


@mcp.tool
def list_projects() -> list[str]:
    access = current_access()  # user_id, agent_id, client_id, scopes
    return projects_of(access.user_id)


@mcp.tool(auth=require_scopes("projects:write"))
def create_project(name: str) -> str: ...


app.mount("/", mcp.http_app(path="/mcp", stateless_http=True))
```

- A call without a token gets 401 with `WWW-Authenticate` pointing to
  `/.well-known/oauth-protected-resource/mcp`, which names GotAuth as the authorization
  server. The client then runs the OAuth flow by itself.
- A tool call whose token lacks a scope gets 403 `insufficient_scope`, so the client can
  ask the user for more access (step-up).
- For the MCP SDK instead of FastMCP, use `mcp_sdk_auth(auth, resource=..., scopes=...)`:
  see the [MCP integration](../integrations/mcp.md).

## Same process or remote

- **Same process** (the MCP server is mounted in the app that runs GotAuth): tokens are
  checked against the database, so revoking access ends it on the next call.
- **Remote** (the MCP server runs elsewhere): pass `issuer="https://api.example.com/api/auth"`
  instead of `auth`, and the server verifies tokens with GotAuth's published keys (JWKS).

!!! warning "Remote servers accept a revoked token until it expires"
    With JWKS alone, a revoked token keeps working at a remote MCP server until it
    expires (`access_token_ttl`, 10 minutes by default). Pass `introspect=True` and
    `introspection_client=(client_id, client_secret)` (a confidential client) to ask
    GotAuth about every token instead, at the cost of one call per request (answers are
    cached for 5 seconds).

## Users stay in control

Users see and revoke the apps they connected: `GET /oauth2/grants` and
`POST /oauth2/grants/revoke`, or the registry's `ConnectedApps` component. Link an MCP
client to an [agent](agents.md) to record which agent acted.

## A complete example

[`examples/fastmcp-server`](https://github.com/gotauth/gotauth/tree/main/examples/fastmcp-server)
is one FastAPI app with GotAuth, a FastMCP server, sign-in and consent pages and a
"Connected apps" page, with steps for MCP Inspector and the Claude connector.
