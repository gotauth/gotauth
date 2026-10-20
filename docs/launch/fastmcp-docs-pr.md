# FastMCP docs: a page for GotAuth

**Their rules** (https://gofastmcp.com/development/contributing, checked 2026-10-16):
- External PRs must link an issue with an auto-close keyword (`Fixes #123`), and the
  author must be assigned to it unless it has the `prs welcome` label. A PR without a
  valid issue link is closed.
- Third-party integrations generally belong in a separate package. GotAuth already is
  one: the page only documents it, and FastMCP's code does not change.
- New doc pages go into `docs/docs.json`.
- AI assistance is allowed, but avoid generated boilerplate. Write the issue and PR
  yourself from these notes, and be ready to answer review.

Provider pages are published under https://gofastmcp.com/integrations/ (for example
https://gofastmcp.com/integrations/propelauth, which follows the "Remote OAuth"
pattern). Find that page's source file in the repo's `docs/` folder before writing
ours, and copy its file name pattern, frontmatter and layout.

**Step 1: open the issue. Step 2: wait for a maintainer's answer. Step 3: the PR.**

## Step 1: the issue

**Title:** Docs: integration page for GotAuth (self-hosted authorization server on the app's own user table)

**Body:**

The integration pages cover identity providers that keep users outside the app
(Auth0, WorkOS, Descope, Keycloak, Supabase and others). Some FastMCP users already
have users in their own database and want the MCP server to sign them in from there.

GotAuth (https://github.com/gotauth/gotauth, MIT) is a Python library that runs the
OAuth 2.1 authorization server inside the app: PKCE, RFC 8707 resources, CIMD and
optional dynamic registration, RFC 9728 metadata. It ships a FastMCP token verifier,
`fastmcp_auth(auth, resource=..., scopes=[...])`, in its own package, so FastMCP's
code would not change.

Would a page under `docs/integrations/` be welcome? It would follow the layout of the
existing provider pages: configuration, testing with a FastMCP client, reading the
user in a tool. I'm the GotAuth maintainer and would keep the page current.

## Step 3: the PR

**Title:** docs: add GotAuth integration page

**Description:**

Fixes #<issue>

Adds an integration page for GotAuth and its entry in `docs/docs.json`. Docs only; no
code changes. The page shows how to protect a FastMCP server with GotAuth, which runs
the authorization server inside the app on the app's own user table. Its code is copied
from GotAuth's `examples/fastmcp-server`, which is tested in GotAuth's CI against
FastMCP 4.1.0.

## The page (docs snippet)

````mdx
---
title: GotAuth and FastMCP
sidebarTitle: GotAuth
description: Sign users in from your own database with an embedded OAuth 2.1 server
---

[GotAuth](https://github.com/gotauth/gotauth) is an open-source Python auth library.
Its `oauth_provider` plugin runs the OAuth 2.1 authorization server inside your
FastAPI app, on your own user table, and its `fastmcp_auth` verifier makes a FastMCP
server accept only GotAuth tokens issued for it.

## Configuration

### Prerequisites

- A FastAPI app with GotAuth, or a new one
- The public URL of your MCP server, for example `https://api.example.com/mcp`

```bash
pip install "gotauth[fastapi,mcp,sqlalchemy,sqlite]"
```

### Step 1: The authorization server

In the module that builds your `GotAuth` object, add the plugin. `MCP_URL` is your MCP
server's public URL and `SCOPES` the scopes your tools use:

```python
from gotauth.plugins.oauth_provider import oauth_provider
```

```python
plugins=[
    oauth_provider(
        mcp=True,
        resources=[MCP_URL],
        scopes=("openid", "profile", "email", *SCOPES, "offline_access"),
        login_page="/sign-in",
        # Claude and other hosted clients register themselves (RFC 7591).
        allow_dynamic_registration=True,
    )
],
```

### Step 2: The FastMCP server

```python
from fastmcp import FastMCP
from fastmcp.server.auth import require_scopes
from fastmcp.exceptions import ToolError

from gotauth.integrations.mcp import current_access, fastmcp_auth

mcp = FastMCP(
    "projects",
    auth=fastmcp_auth(auth, resource=MCP_URL, scopes=["projects:read"]),
)
```

Mount the MCP app at the root of the host that `MCP_URL` names, next to GotAuth's
`auth.well_known()` app, so the RFC 9728 document is served at
`/.well-known/oauth-protected-resource/mcp`. The full app:
[examples/fastmcp-server](https://github.com/gotauth/gotauth/tree/main/examples/fastmcp-server).

## Accessing user information

```python
def user_id() -> str:
    access = current_access()
    if access is None or access.user_id is None:
        # A client_credentials token acts for no user, and the projects are users'.
        raise ToolError("this tool needs a user's token")
    return access.user_id

@mcp.tool
def list_projects() -> list[Project]:
    """The signed-in user's projects."""
    return projects_of(user_id())
```

`projects_of` and `Project` are the example app's own data. `current_access()` returns the user id, agent id, client id and scopes of the token.
A tool with `auth=require_scopes("projects:write")` answers a token without that scope
with an HTTP 403 `insufficient_scope`, so the client can ask for it.
````

Note on the snippet: the other provider pages title themselves "<Provider>" plus a
handshake symbol plus "FastMCP". Match whatever title form the current pages use.
