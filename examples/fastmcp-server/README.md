# FastMCP server with GotAuth

An MCP server whose users sign in with GotAuth, in one FastAPI app:
- **GotAuth** is the OAuth 2.1 authorization server for MCP clients: `oauth_provider(mcp=True)`, with sign-in and consent pages.
- **The FastMCP server** at `/mcp` accepts only GotAuth access tokens issued for it, through [`fastmcp_auth`](../../src/gotauth/integrations/mcp/README.md).
  - `list_projects` needs `projects:read`.
  - `create_project` also needs `projects:write`.
- **A "Connected apps" page** lists every MCP client the user allowed. Revoking one ends its access on the next call.

All of the auth setup is in [app/auth.py](app/auth.py); the pages and the MCP server are in [app/main.py](app/main.py).

Built with FastMCP 4.1.0, FastAPI 0.143 and Python 3.14 (checked 2026-10-13), for MCP authorization revision 2026-07-28.

## How it works
1. **An MCP client calls `/mcp` without a token.** It gets a 401 whose `WWW-Authenticate` header points to `/.well-known/oauth-protected-resource/mcp`. That document names GotAuth (`/api/auth`) as the authorization server.
2. **The client starts the OAuth flow,** with PKCE and `resource=<this server>/mcp`.
   - The browser goes to `/sign-in` if needed, then to GotAuth's consent page.
   - The client gets a token whose audience is the MCP server.
3. **Tools read the caller** with `current_access()`: user, agent, client and scopes.
4. **A missing tool scope is a 403** `insufficient_scope` naming every scope the call needs, so the client can ask the user for more.
5. **"Connected apps"** calls `POST /api/auth/oauth2/grants/revoke`. Tokens are checked in the same process, so the next MCP call is a 401.

The sign-in page and the "Connected apps" page send their changes straight to GotAuth's JSON endpoints, which check the `Origin` header ([app/static/app.js](app/static/app.js)).

## Run it

From the repository root, in the dev container. `UV_PROJECT_ENVIRONMENT=.venv` keeps the example's environment apart from the library's.

```bash
./dev.sh --ports bash
cd examples/fastmcp-server && export UV_PROJECT_ENVIRONMENT=.venv && uv sync --locked
[ -f .env ] || echo "GOTAUTH_SECRET=$(uv run gotauth secret)" > .env   # once
set -a && . ./.env && set +a                    # nothing else loads .env
uv run gotauth migrate --auth app.auth:auth && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The app prints the MCP server's URL and the client id it registered for MCP Inspector. Open http://localhost:8000 to create an account.

## MCP Inspector

1. On the host, run `npx @modelcontextprotocol/inspector`.
2. Pick the "Streamable HTTP" transport and enter `http://localhost:8000/mcp`.
3. Under the authentication settings, enter the printed client id and the scope `projects:read projects:write`.
4. Connect. The browser opens the sign-in page, then the consent page.
5. List the tools and call `list_projects`.

The app registers that client up front because MCP Inspector's callback is a loopback address (`http://localhost:6274/oauth/callback`). Client ID metadata documents on loopback hosts are refused. Inspector runs discovery, the token request and the MCP calls from its own page, so the app allows CORS from `http://localhost:6274`, without credentials.

## Claude (custom connector)

Claude reaches the server from the internet, so it needs a public https URL:
1. Start a tunnel to port 8000, for example `cloudflared tunnel --url http://localhost:8000`.
2. Set `BASE_URL` in `.env` to the tunnel's https URL. Load it again (`set -a && . ./.env && set +a`), then restart the app. Tokens are issued for `<BASE_URL>/mcp`, and you sign in at `<BASE_URL>`, not at localhost.
3. In Claude, add a custom connector with the URL `<BASE_URL>/mcp`. Claude registers itself (with a client ID metadata document, or dynamic registration, which is on in this example), then opens the sign-in and consent pages.

A client that registered dynamically can only get the scopes it asked for at registration, so the `projects:write` step-up in the clip needs a client ID metadata document or a registration that asked for both scopes. Issue #33 tracks lifting that limit.

## The clip

1. Claude: "List my projects." Claude asks to connect, and the browser shows GotAuth's sign-in, then the consent page for `projects:read`.
2. Claude lists the three demo projects.
3. "Create a project called Launch." The server answers 403 `insufficient_scope`. Claude asks for `projects:write` and the consent page shows the extra scope.
4. Claude creates the project.
5. In the app, open "Connected apps" and revoke Claude.
6. "List my projects" again: the next call is a 401, and Claude asks to connect again.

## Tests

```bash
cd examples/fastmcp-server && UV_PROJECT_ENVIRONMENT=.venv uv run pytest
```

[tests/test_mcp_flow.py](tests/test_mcp_flow.py) runs the whole flow with httpx, in process, on a SQLite file:
- the 401 and the discovery documents
- sign-up, consent and code exchange for the MCP Inspector client
- the tool calls, and the 403 step-up for `create_project`
- revoking in "Connected apps", then a 401

CI runs it in the `examples` job.
