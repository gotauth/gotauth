from fastmcp import FastMCP
from gotauth.integrations.mcp import fastmcp_auth
from gotauth.plugins.oauth_provider import oauth_provider

auth = GotAuth(
    ...,  # database, secret and base_url as above
    plugins=[oauth_provider(mcp=True, resources=["https://mcp.example.com/mcp"])],
)
app.mount("/", auth.well_known())   # RFC 8414 metadata at the host root, for MCP clients

mcp = FastMCP(
    "projects",
    auth=fastmcp_auth(auth, resource="https://mcp.example.com/mcp", scopes=["projects:read"]),
)
