# GotAuth: project overview

> **Packages:** [`gotauth` on PyPI](https://pypi.org/project/gotauth/) (the library) and [`@gotauth/client` on npm](https://www.npmjs.com/package/@gotauth/client) (the typed client). **Code:** [github.com/gotauth/gotauth](https://github.com/gotauth/gotauth). **Site:** [gotauth.ablacky.com](https://gotauth.ablacky.com).
>
> **Engineering plan:** [plan/](plan/README.md). It is split into **work packages that several AI agents can build in parallel**:
> - [CONTRACTS.md](plan/CONTRACTS.md): shared interfaces
> - [AGENT-RULES.md](plan/AGENT-RULES.md): rules every agent follows
> - [wp/](plan/wp/): one brief per work package
>
> **Evidence:** [validation-research.md](research/validation-research.md) (public sources).

## One-line pitch
**"Got auth? GotAuth is open-source auth for Python AI backends: users, sessions, social login, 2FA, passkeys, organizations, API keys, agent identities and a built-in OAuth 2.1 server for your MCP servers. All of it lives in your own database."**

It's an open-source Python library (MIT) that lives inside your FastAPI app, the way Better Auth lives inside a TypeScript app. It is an independent project with its own roadmap.

## Why now
- **The incumbent stopped adding features.** fastapi-users entered maintenance mode on 2025-10-25 and still gets about 1.27M downloads a month. Its maintainer wrote that Python has "no great, framework-agnostic and exhaustive solution" for auth.
- **AI coding agents write Python auth from scratch.** In the Amplifying benchmark (2,430 prompts), Claude Code hand-rolled Python auth 100% of the time, using JWT, passlib and python-jose.
- **MCP servers need an authorization server, and no Python library offers an embeddable one for FastAPI and ASGI apps, on your own user table, with CIMD.**
  - The MCP Python SDK's [authorization docs](https://py.sdk.modelcontextprotocol.io/run/authorization/) say of the authorization server: "You don't write this. It's your identity provider."
  - FastMCP's own OAuth provider "requires significant additional configuration for user management".
  - Every built-in FastMCP provider hands sign-in to a separate identity provider (hosted ones such as Auth0, WorkOS, Clerk and Descope, or a Keycloak server you run). None of them uses your app's own user table.
- **The market is big.** In the JetBrains Python Developers Survey 2024, 38% of all respondents use FastAPI, 39% use SQLAlchemy and 49% use PostgreSQL. FastAPI gets about 358M downloads a month.

## Positioning
**Lead with agent-era auth.** GotAuth is a full FastAPI auth library. Its headline and its edge are three things the alternatives don't offer:
- API keys
- agent identities
- a built-in OAuth 2.1 server for MCP servers

| GotAuth is... | ...not |
|---|---|
| A FastAPI-first library inside your app, with real FastAPI routes in your OpenAPI | A separate auth service (Keycloak, Ory, SuperTokens core) |
| Pythonic: snake_case, Pydantic v2, `Annotated` dependencies, Alembic migrations | A line-by-line port of a TypeScript API |
| An OAuth 2.1 / MCP authorization server built on *your* user table | A hosted identity provider (Auth0, WorkOS, Clerk) |
| Free organizations, RBAC, API keys and agent features | Pay-per-SSO-connection, or a surcharge for AI-agent features |
| Standard tokens and claims (`sub`, `act`, `azp`, scopes) that any authorization or policy layer can read | Locked to one policy engine or vendor |
| Focused on FastAPI and ASGI (Starlette, Litestar) | A replacement for allauth on Django |

### Why not X?
| Alternative | What it is | Why GotAuth |
|---|---|---|
| [fastapi-users](https://github.com/fastapi-users/fastapi-users) | 6.2k stars; maintenance mode since 2025-10-25; FastAPI only; no 2FA, passkeys, orgs or API keys | Active roadmap, 2FA, passkeys, orgs, API keys and an OAuth server, plus `gotauth import fastapi-users` to move over |
| [reauth](https://github.com/frankie567/reauth) | By the fastapi-users author; 11 stars; early building blocks (email OTP, TOTP, social, sessions); no passwords or framework wrappers yet | A complete stack today (passwords, sessions, storage, FastAPI integration) plus the agent and MCP features |
| [better-auth-server](https://github.com/oumarbarry/better-auth-py) | 3 stars; a parity port of Better Auth TypeScript, released 2026-09; about 3,000 tests in CI; no security policy; its OAuth server has no CIMD yet | A Pythonic API, a security process, CIMD and MCP helpers, and no dependence on another project's release cadence |
| [qulf](https://github.com/qulflabs/qulf), auth101, userharbor | 2-15 stars; early | Agent and MCP features, docs written for coding agents, the `gotauth check` tool |
| Auth0, Clerk, WorkOS, Stytch | Hosted; sign-in runs on the vendor's pages, and the Python SDKs wrap the vendor API | Free, and your data stays in your database. Enterprise SSO costs $60-125 per connection per month (Auth0, Clerk, WorkOS), Clerk's advanced organization features are a $100/mo add-on, and Auth0's AI Agents add-on adds 50% to the plan price |
| django-allauth | Excellent, but Django only; its OIDC provider supports DCR and CIMD since 2026 | Not competing on Django |

## Architecture (summary; the details are in CONTRACTS.md)
```
request -> adapter (FastAPI router | ASGI app | auth.api.<call>) -> AuthRequest
        -> rate limit -> origin/CSRF check -> input model (Pydantic) -> before hooks
        -> endpoint handler (core or plugin) -> Adapter (SQLAlchemy | memory) -> after hooks
        -> AuthResponse (JSON + Set-Cookie) -> adapter
```
- **One distribution, `gotauth`, with extras:** `[fastapi]`, `[starlette]`, `[litestar]`, `[sqlalchemy]`, `[postgres]`, `[sqlite]`, `[redis]`, `[argon2]`, `[bcrypt]`, `[passkey]`, `[mcp]`, `[smtp]`.
- **Tables are prefixed `auth_`** by default (`auth_user`, `auth_session`, ...), so they never clash with an app's existing `user` table.
- **Core dependencies:** pydantic>=2, httpx, cryptography and PyJWT. The last two are there so GotAuth never hand-rolls cryptography: AES-GCM for secrets at rest, plus JWT signing and verification.
- **Python >= 3.11.**

```python
from typing import Annotated

from fastapi import Depends, FastAPI
from gotauth import GotAuth, User
from gotauth.storage.sqlalchemy import sqlalchemy_adapter
from gotauth.social import github, google
from gotauth.plugins.api_key import api_key
from gotauth.plugins.two_factor import two_factor
from gotauth.plugins.passkey import passkey
from gotauth.plugins.organization import organization
from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.plugins.agent import agent

auth = GotAuth(
    database=sqlalchemy_adapter(engine),
    secret=settings.GOTAUTH_SECRET,
    base_url="https://api.example.com",
    email_password={"enabled": True, "require_email_verification": True},
    social_providers=[github(client_id=..., client_secret=...), google(client_id=..., client_secret=...)],
    plugins=[
        api_key(), two_factor(), passkey(), organization(), agent(),
        oauth_provider(mcp=True, resources=["https://mcp.example.com/mcp"]),
    ],
)

app = FastAPI()
app.include_router(auth.fastapi.router(), prefix="/api/auth")
app.mount("/", auth.well_known())   # RFC 8414 metadata at the host root, for MCP clients

CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]

@app.get("/projects")
async def list_projects(user: CurrentUser):
    ...
```

Protecting a FastMCP server with your own users:
```python
from fastmcp import FastMCP
from gotauth.integrations.mcp import fastmcp_auth

mcp = FastMCP(
    "projects",
    auth=fastmcp_auth(auth, resource="https://mcp.example.com/mcp", scopes=["projects:read"]),
)
```
The API shown is planned and may change during the build; [plan/CONTRACTS.md](plan/CONTRACTS.md) is the source of truth.

## Roadmap
The build is split into **36 work packages**: 30 for v0.1 and 6 for later. The graph, the milestones and the status of each package are in [plan/README.md](plan/README.md).

| Phase | What it builds | Ends with |
|---|---|---|
| **0: Foundation** | F1 scaffold, F2 contracts + testing kit, F3 crypto; G1 landing page; R1 validation addendum | **M0:** contracts frozen |
| **1: Core** | C1 pipeline, C2 email + password, C3 sessions, C4 social login, S1 SQLAlchemy + CLI, D1 email, D2 UI part 1, P1 API keys, G3 `gotauth check` | **M1:** core green |
| **2: Integration** | A1 FastAPI, A2 Starlette/Litestar, O1 OAuth 2.1 server, G4 examples part 1, Q1 security | **M2:** end-to-end demo |
| **3: Breadth + hardening** | P2 2FA, P3 passkeys, P4 magic link, P5 organizations, P6 admin, O2 MCP, O3 agent identities, I1 fastapi-users import, D2 UI part 2, G4 examples part 2, G2 docs, Q1 security, Q2 e2e + agent-install test | **M3:** v0.1 |
| **Later** | O4 delegation chains, E1 SSO + SCIM, A3 Flask/Django, S2 SQLModel/Django ORM, B1 Better Auth interop | When users ask for them |

## Security
GotAuth is an auth library, so security work runs alongside the features instead of after them:
- fail-closed defaults; secrets and tokens hashed at rest
- a [threat model](security/threat-model.md) and an [OWASP ASVS 5.0 Level 2 mapping](security/asvs.md), with every mitigation linked to a test
- property and fuzz tests in `tests/security`
- an OpenID conformance run for the OAuth server ([conformance](security/conformance/README.md))
- PyPI and npm releases with provenance (PEP 740 attestations), and private vulnerability reporting ([SECURITY.md](../SECURITY.md))

## Scope
- **No Better Auth parity goal.** GotAuth has its own Pythonic API and release cadence.
- **The MCP auth spec moves;** O1 and O2 record the spec revision they target.
- **Django is out of scope;** django-allauth serves it well.
