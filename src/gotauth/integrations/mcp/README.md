# gotauth.integrations.mcp

Protect a Python MCP server with GotAuth access tokens. Work package O2, CONTRACTS
12.4. Built against FastMCP 4.0.10 and the MCP Python SDK (`mcp`) 2.3.0, checked
2026-10-13, for MCP authorization revision 2026-07-28. Needs
`pip install "gotauth[mcp]"`; `import gotauth` imports neither framework.

The MCP server:
- accepts only GotAuth access tokens issued for its URL (`aud`)
- advertises GotAuth as its authorization server (RFC 9728)
- answers 401 and 403 with the challenges MCP clients need to sign in and step up
- gives tools the user, agent, client and scopes

## FastMCP

```python
from fastmcp import FastMCP
from fastmcp.server.auth import require_scopes

from gotauth.integrations.mcp import current_access, fastmcp_auth

RESOURCE = "https://api.example.com/mcp"

mcp = FastMCP(
    "projects",
    auth=fastmcp_auth(auth, resource=RESOURCE, scopes=["projects:read"]),
)


@mcp.tool
def list_projects() -> list[str]:
    access = current_access()  # user_id, agent_id, client_id, scopes, jti
    ...


@mcp.tool(auth=require_scopes("projects:write"))
def create_project(name: str) -> str: ...


app = mcp.http_app(path="/mcp", stateless_http=True)
```

The GotAuth app needs `oauth_provider(mcp=True, resources=[RESOURCE], scopes=[...])`
with the scopes your tools use. Mount the MCP app at the root of the host the
resource URL names: the RFC 9728 document is served at
`/.well-known/oauth-protected-resource/mcp`. Otherwise, serve
`protected_resource_metadata(...)` at that path yourself.

A call to `create_project` with a token that lacks `projects:write` is an HTTP 403
with `error="insufficient_scope"`, so the client can ask the user for the extra scope.
FastMCP on its own answers it with a JSON-RPC error instead. To find a tool's
`require_scopes` checks, GotAuth looks the tool up the way FastMCP's stdio transport
does, through FastMCP's internal `_current_transport` context. The tests cover it.

## The MCP SDK

```python
from mcp.server.mcpserver import MCPServer

from gotauth.integrations.mcp import mcp_sdk_auth

settings, verifier = mcp_sdk_auth(auth, resource=RESOURCE, scopes=["projects:read"])
server = MCPServer("projects", auth=settings, token_verifier=verifier)
app = verifier.guard(
    server.streamable_http_app(stateless_http=True),
    tool_scopes={"create_project": ["projects:write"]},
)
```

`verifier.guard(...)` answers every 401 and 403 and serves the RFC 9728 document. The
SDK's own challenges are wrong (python-sdk #3103), so always wrap the app. The SDK has
no per-tool scopes, so `tool_scopes` names them.

## Same process or remote

| | `auth=` (same process) | `issuer=` (another process) |
|---|---|---|
| Checks | O1's `verify_access_token`: signature, `typ`, `iss`, `exp`, `aud`, revocation, disabled clients and agents | Discovery and JWKS from the issuer. Each key is used only with its own `alg`; `none` and `HS*` never verify. An unknown `kid` refetches the JWKS at most once per 30 seconds |
| Revocation | Seen on the next call | Seen when the token expires (10 minutes by default). With `introspect=True` and `introspection_client=(client_id, client_secret)`, seen within 5 seconds |
| Issuer down | Not applicable | 503, never a 401 |

## Challenges

`<scopes>` is the `scopes` argument without `offline_access`; `<url>` is the RFC 9728
document's URL.

| Case | Status | `WWW-Authenticate` |
|---|---|---|
| No token | 401 | `Bearer resource_metadata="<url>", scope="<scopes>"` (no `scope` when empty) |
| Bad, expired or revoked token, or one for another resource | 401 | `Bearer error="invalid_token", resource_metadata="<url>", scope="<scopes>"` |
| Missing scope (server or tool) | 403 | `Bearer error="insufficient_scope", scope="<every scope the call needs>", resource_metadata="<url>"` |

## `GotAuthAccess`

`current_access()` returns it in a tool, or `None` outside a request. The fields:
- `user_id`: never an agent or client id. A `client_credentials` token has none.
- `agent_id`: from the `act.sub` claim.
- `client_id`, `scopes`, `jti`, `expires_at`.

The framework's own access token (`get_access_token()`) carries the same fields in
`claims["gotauth"]`.

## Tests

`tests/integrations/mcp/`:
- FastMCP and the SDK against tokens from O1's real code flow, in process.
- The remote verifier against a fake issuer: rotation, the refetch limit,
  introspection, pinned algorithms.
- The exact header strings above.
