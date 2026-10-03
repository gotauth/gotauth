# GotAuth: build plan (strategy and launch)

> **Name:** GotAuth ("got auth?").
> - **Packages:** PyPI `gotauth`, npm `gotauth` (for the future UI/client package).
> - **Accounts:** GitHub org `gotauth`; X, Bluesky and LinkedIn handles.
> - **Domain:** `gotauth.dev`.
>
> PyPI, npm, the GitHub org and the domain were all free on 2026-10-03 (`gotauth.com` is taken). **Claim them on day 1.**
>
> **Engineering plan:** [plan/](plan/README.md). It is split into **work packages that several AI agents can build in parallel**:
> - [CONTRACTS.md](plan/CONTRACTS.md): shared interfaces
> - [AGENT-RULES.md](plan/AGENT-RULES.md): rules every agent follows
> - [wp/](plan/wp/): one brief per work package
>
> **Evidence:** [validation-research.md](research/validation-research.md) (public evidence, no interviews).

## One-line pitch
**"Got auth? GotAuth is open-source auth for Python AI backends: users, sessions, social login, 2FA, passkeys, organizations, API keys, agent identities and a built-in OAuth 2.1 server for your MCP servers. All of it lives in your own database."**

It's an open-source Python library (MIT) that lives inside your FastAPI app, the way Better Auth lives inside a TypeScript app. It is an independent project with its own roadmap.

## Why now
- **The incumbent stopped adding features.** fastapi-users entered maintenance mode on 2025-10-25 and still gets about 1.27M downloads a month. Its maintainer wrote that Python has "no great, framework-agnostic and exhaustive solution" for auth.
- **AI coding agents write Python auth from scratch.** In the Amplifying benchmark (2,430 prompts), Claude Code hand-rolled Python auth 100% of the time, using JWT, passlib and python-jose.
- **MCP servers need an authorization server, and Python has no embeddable one.**
  - The MCP Python SDK says of the authorization server: "You don't write this. It's your identity provider."
  - FastMCP's own OAuth provider "requires significant additional configuration for user management".
  - Every built-in FastMCP provider is a hosted service (Auth0, WorkOS, Clerk, Descope, ...).
- **The market is big.** FastAPI is used by 38% of Python web developers (JetBrains 2024) and gets about 358M downloads a month. SQLAlchemy is used by 39%, Postgres by 49%.

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

### Why not X? (validation gate G8; becomes the public comparison page)
| Alternative | What it is | Why GotAuth |
|---|---|---|
| [fastapi-users](https://github.com/fastapi-users/fastapi-users) | 6.2k stars; maintenance mode since 2025-10-25; FastAPI only; no 2FA, passkeys, orgs or API keys | Active roadmap, 2FA, passkeys, orgs, API keys and an OAuth server, plus `gotauth import fastapi-users` to move over |
| [reauth](https://github.com/frankie567/reauth) | By the fastapi-users author; 11 stars; early building blocks (email OTP, TOTP, social, sessions); no passwords or framework wrappers yet | A complete stack today (passwords, sessions, storage, FastAPI integration) plus the agent and MCP features |
| [better-auth-server](https://github.com/oumarbarry/better-auth-py) | 3 stars; a parity port of Better Auth TypeScript, released 2026-09 | A Pythonic API, published tests, a security process, and no dependence on another project's release cadence |
| [qulf](https://github.com/qulflabs/qulf), auth101, userharbor | 2-15 stars; early | Agent and MCP features, docs written for coding agents, the `gotauth check` tool |
| Auth0, Clerk, WorkOS, Stytch | Hosted; Python SDKs mostly verify tokens | Free, and your data stays in your database. Clerk charges $100/mo for orgs, Clerk and WorkOS charge $75-125 per SSO connection per month, and Auth0's agent features cost +50% |
| django-allauth | Excellent, but Django only | Not competing on Django |

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

## Execution: phases with parallel agents
The build is split into **36 work packages**: 30 to reach v0.1, plus 6 for later. The full graph, schedule and agent instructions are in [plan/README.md](plan/README.md).

| Phase | Runs in parallel | Ends with |
|---|---|---|
| **0: Foundation + demand test** (week 1) | F1 scaffold -> F2 contracts + testing kit, F3 crypto; G1 landing page; R1 validation addendum | **M0:** contracts frozen, and the demand test result |
| **1: Core** (weeks 2-3) | C1 pipeline, C2 email + password, C3 sessions, C4 social login, S1 SQLAlchemy + CLI, D1 email, D2 UI part 1; P1 API keys and G3 `gotauth check` start early (week 3) because they need only the testing kit | **M1:** core green |
| **2: Integration** (week 4) | A1 FastAPI, A2 Starlette/Litestar, O1 OAuth 2.1 server, G4 example part 1, Q1 starts | **M2:** end-to-end demo + **hero clip** |
| **3: Breadth + hardening** (weeks 5-7) | P2 2FA, P3 passkeys, P4 magic link, P5 orgs, P6 admin, O2 MCP, O3 agent identities, I1 fastapi-users import, D2 UI part 2, G4 example part 2, G2 docs, Q1 security, Q2 e2e + agent-install, G5 launch content | **M3:** v0.1 launch |
| **4-5** (after the post-launch test) | O4 delegation chains, E1 SSO + SCIM, A3 Flask/Django, S2 SQLModel/Django ORM, B1 Better Auth interop, X Cloud | Only on demand |

**About 7 weeks to v0.1 with 4 agents running at once and steady reviewing.** If you're part-time, run 2 agents at a time; that's about 12 weeks.

### Your lane (things only you do)
| When | You do |
|---|---|
| Day 1 | Claim the GitHub org `gotauth`, `gotauth.dev`, npm `gotauth` and the X/Bluesky/LinkedIn handles. Once F1 exists, publish a minimal but real `gotauth 0.0.1` to PyPI (README, license, metadata). PyPI's name-squatting policy (PEP 541) frowns on empty placeholders |
| Phase 0 | Put the landing page live (G1). Post #1: "AI agents still write Python auth with passlib. I'm building GotAuth: auth for Python AI backends and MCP servers." **Run the demand test** (below) |
| Every merge | Review the PR (acceptance tests + write scope), merge in dependency order, update the status table |
| M1 | Technical thread: "why session tokens should be hashed in your database" |
| M2 | **Record the hero clip** from `examples/fastapi-nextjs`; publish `uvx gotauth check` |
| O2 merged | Record the MCP clip; open the FastMCP docs PR |
| M3 | Launch week (checklist below) |
| M3 + 3 weeks | The post-launch test |

## Validation gates (no interviews)
**Measured on 2026-10-03.** The details are in [validation-research.md](research/validation-research.md).

| Gate | Threshold | Result |
|---|---|---|
| G1 complaints | >= 10 independent public complaints in 12 months, on >= 3 platforms | Marginal (10) |
| G2 reactions | >= 50 total reactions on Python-auth gap requests in 24 months | Pass (57) |
| G2b single request | One request with >= 100 reactions | Fail (26) |
| G3 DIY | >= 15 auth repos with 25+ stars created 2024-2026 | Pass (about 17) |
| G4 AI agents | A published benchmark shows agents hand-roll Python auth | Pass (100%) |
| G5 incumbent | The main library has > 1M downloads/month while in maintenance | Pass (1.27M) |
| G6 HN | A Python-auth story with >= 50 points, 2024-2026 | Fail (best: 3 points) |
| G7 open lane | No rival with >= 500 stars or >= 50k downloads/month | Pass, fragile |
| G8 differentiation | A written "why not X" | Met (above), refined by R1 |

The demand is real but quiet, so a **hard demand test runs before Phase 1.**

**Demand test, Phase 0.** Within 7 days of the first posts, any one of these passes it:
- >= 30 upvotes on one r/FastAPI or r/mcp post
- >= 30 waitlist signups
- >= 5 independent "I need this" replies
- >= 20 HN points

If it fails, rewrite the pitch once, leading with the fastapi-users migration, and post again. If it fails a second time, park GotAuth before Phase 1. About a week of work is spent at that point.

**Competitor watch** (monthly, and before each phase). The triggers are:
- reauth ships password auth + FastAPI integration + 1.0
- better-auth-server passes 500 stars
- the FastAPI team ships an official auth library
- Better Auth announces Python support

If any of these fires before M2, narrow GotAuth to the agent layer: API keys, the OAuth 2.1/MCP server and agent identities, shipped as plugins that can sit on other user stores.

**Post-launch test** (3 weeks after M3). Any one of these passes it:
- >= 200 GitHub stars
- >= 2,000 PyPI downloads in 30 days (pypistats, without mirrors)
- >= 5 inbound integration requests
- a merged FastMCP docs PR listing GotAuth

If none happen, stop adding features, keep doing security fixes, and refocus.

## Launch week checklist (all free; drafts come from G5)
1. **Show HN:** "Show HN: GotAuth - login for your Python MCP server from your own user table"
2. **r/FastAPI.** Launch posts are tolerated and typically get 10-45 upvotes.
3. **r/Python.** Requires the Showcase format: *What My Project Does*, *Target Audience*, *Comparison*.
4. **r/mcp**
5. **Newsletters and podcasts:**
   - [PyCoder's Weekly submission form](https://pycoders.com/submissions)
   - a [Python Bytes](https://pythonbytes.fm/) topic suggestion
   - a [Talk Python](https://talkpython.fm/) guest pitch
6. **A Dev.to / Hashnode tutorial:** "Login for your FastMCP server from your own user table in 10 lines"
7. **Distribution through the frameworks:**
   - a PR adding GotAuth to FastMCP's auth-provider docs (the highest-value item)
   - an example for the MCP Python SDK
8. **Talks:** the PyCon US 2027 call for proposals (expected Oct-Dec 2026; see [pythondeadlin.es](https://pythondeadlin.es/)) with "Auth for MCP servers in Python".
9. **Later:** awesome-fastapi (wants projects at least a year old) and awesome-python (judged by PyPI downloads).

**Hero clips:**
1. **MCP login.** Claude connects to your FastMCP server -> your app's passkey login and consent screen -> the tools work -> you revoke access in your app -> the next call gets a 401.
2. **Agent split screen.** The same "add GitHub login and API keys to this FastAPI app" prompt, with and without GotAuth's skill. Without it, the agent writes about 200 lines with passlib and python-jose; with it, about 15 lines. Check current passlib and python-jose maintenance facts before posting.
3. **`uvx gotauth check`** on your own demo app: the score, then the fixes.

## Marketing routine (every week)
| When | What |
|---|---|
| Mon | A progress post with a screenshot or clip |
| Wed | A technical thread (CIMD for MCP clients, hashed session tokens, why `act` claims matter for agents, no account enumeration) |
| Fri | A 15-30 second demo clip |
| Same day | Helpful answers to Python and MCP auth questions on GitHub issues, r/FastAPI and r/mcp. Help first; mention GotAuth only when it fits |
| Monthly | A changelog post and the competitor watch |

**Metrics (free):**
- GitHub stars and traffic
- PyPI downloads (pypistats)
- waitlist size
- `gotauth check` runs (only a counter you can see, such as PyPI downloads of the checker; no telemetry in the tool)
- **inbound integration requests**, the most important one

**Cash budget:** about $12 a year for `gotauth.dev`. Everything else uses free tiers.

## Money (later, only on demand)
- **Open-core, the Better Auth way:** the library is free (MIT).
- **GotAuth Cloud** ([X-cloud.md](plan/wp/X-cloud.md)), built only after production users ask for it:
  - hosted admin dashboard (users, sessions, orgs, API keys, agents)
  - audit log search and retention
  - abuse and bot detection
  - SSO connection management
  - email delivery
  - billing through Polar (merchant of record)
- **Pricing to test:** Free, Pro $29/mo, Team $99/mo.

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| reauth or an official FastAPI library wins on brand | Lead with the agent and MCP features they don't have. If a watch trigger fires, narrow to the agent layer as plugins |
| A security bug in an auth library | Q1 from Phase 1:<br>- threat model and OWASP ASVS L2 mapping<br>- property and fuzz tests<br>- OpenID conformance run for the OAuth server<br>- PyPI attestations and a SECURITY.md advisory process<br>Fail-closed defaults throughout |
| Spec treadmill (the MCP auth spec moves; Better Auth releases weekly) | No Better Auth parity goal. Track only MCP auth spec revisions; O1 and O2 record the spec version they target |
| Demand stays quiet (G2b and G6 fail) | Hard demand test before Phase 1, the post-launch test, park the project if they fail |
| You are the only reviewer | At most 4 agent slots (2 if part-time); follow the cut list in the plan README; Q1 reviews security-critical PRs as they land |
