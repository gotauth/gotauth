# GotAuth problem validation (public evidence, no interviews)

> **Snapshot:** 2026-10-03.
>
> **Sources:**
> - Hacker News (Algolia API)
> - GitHub issues and repositories (search API)
> - PyPI JSON and pypistats
> - the Amplifying.ai benchmark
> - framework docs
> - web search
>
> Reddit could not be fetched directly. The r/FastAPI posts come from the PullPush archive, so their scores are snapshots and probably understate current votes. r/Python, r/django and r/flask are mostly uncovered.
>
> Engagement numbers are as of the snapshot date. Entries are paraphrased unless quoted.

## Verdict: **a real gap with quiet demand, and a crowd of early challengers**
- **The gap is clear.**
  - The main FastAPI auth library stopped adding features.
  - AI coding agents hand-roll Python auth.
  - Python MCP servers have no embeddable authorization server.
- **The demand is quiet.** No viral HN story, and the biggest single Python-auth request has 26 reactions.
- **At least five 2026 projects are chasing the same opening.** None has more than 21 stars.

| Gate | Threshold | Result | Evidence |
|---|---|---|---|
| G1 complaints | >= 10 independent public complaints in 12 months, on >= 3 platforms | **Marginal** | 10 items: 8 on Reddit, 1 on GitHub, 1 on HN (that one is about Flask and Django) |
| G2 reactions | >= 50 total reactions on Python-auth gap requests in 24 months | **Pass** | 57 (5 + 4 + 3 + 12 + 7 + 26) |
| G2b single request | One Python-support request with >= 100 reactions | **Fail** | Highest is 26. For contrast, a NestJS request on Better Auth has 237 |
| G3 DIY | >= 15 auth-focused FastAPI libraries or boilerplates with 25+ stars, created 2024-2026 | **Pass** | About 17, plus 8 "Better Auth for Python" ports or bridges |
| G4 AI agents | A published benchmark shows agents hand-roll Python auth | **Pass** | Amplifying: 100% custom (JWT + passlib + python-jose) |
| G5 incumbent | The main FastAPI auth library has > 1M downloads/month while in maintenance | **Pass** | fastapi-users: 1.27M/month |
| G6 HN interest | A Python-auth story with >= 50 points, 2024-2026 | **Fail** | Best Python-specific story: 3 points |
| G7 open lane | No Better-Auth-style Python library with >= 500 stars or >= 50k downloads/month | **Pass, fragile** | better-auth-server matches the feature scope but has 3 stars and 530 downloads/month. Re-check monthly |
| G8 differentiation | A written answer to "why not better-auth-server, reauth, AuthX, or the fastapi-users successor?" | **Met** | The "Why not X?" table in [build-plan.md](../build-plan.md); R1 refines it |

**Still to do:** the one-time **demand test** in Phase 0. Within 7 days of the first posts, any one of these passes it:
- >= 30 upvotes on one r/FastAPI or r/mcp post
- >= 30 waitlist signups
- >= 5 "I need this" replies
- >= 20 HN points

## Strongest evidence
### The incumbent stopped
- **fastapi-users entered maintenance mode on 2025-10-25.** Only security fixes since; 6,247 stars; 1.27M downloads in the last 30 days.
  - The maintainer's reason: "there is no great, framework-agnostic and exhaustive solution to implement authentication in Python right now".
  - The docs say a new toolkit "will ultimately supersede FastAPI Users".
  - Sources: https://github.com/fastapi-users/fastapi-users/discussions/1543 and https://fastapi-users.github.io/fastapi-users/latest/
- **The fastapi-users author's new project, reauth,** was created 2026-05-09, is at 0.4.2 and has 11 stars. That it is the announced successor is an inference; the announcement doesn't name it. https://github.com/frankie567/reauth

### AI coding agents hand-roll Python auth
- **Amplifying.ai benchmark** (2,430 prompts, 3 models, Feb 2026):
  - Python auth was "100% Custom/DIY: JWT + passlib + python-jose".
  - When asked to "add auth" in Python, the agent writes JWT and bcrypt code from scratch.
  - For contrast, Next.js picks NextAuth 91% of the time.
  - https://amplifying.ai/research/claude-code-picks/report

### The MCP authorization gap (agent-era lead)
- **MCP Python SDK** (24.5k stars, about 219M downloads/month).
  - It handles token verification and RFC 9728 discovery metadata.
  - Its docs say of the authorization server: "You don't write this. It's your identity provider."
  - Server-side support for client ID metadata documents (CIMD) is an open issue: https://github.com/modelcontextprotocol/python-sdk/issues/1801 (since 2025-12-18).
  - Docs: https://github.com/modelcontextprotocol/python-sdk
- **FastMCP** (28k stars, about 50M downloads/month).
  - Its full `OAuthProvider` "requires significant additional configuration for user management". https://gofastmcp.com/servers/auth/authentication
  - Its built-in providers are all hosted services: Auth0, AWS, Azure, Clerk, Descope, Discord, GitHub, Google, HuggingFace, Keycloak, OCI, PropelAuth, Scalekit, Supabase, WorkOS.
- **No mature embeddable Python option.**
  - Authlib is a toolkit you assemble yourself.
  - django-oauth-toolkit and allauth's identity provider are Django-only.
  - Keycloak and Ory are separate services.
- **No mainstream open-source Python library** for API keys or agent identities. The current options are hosted (Unkey, Clerk and Auth0 machine-to-machine).
- **Spec context:** the MCP 2026-07-28 revision reportedly moves client registration toward CIMD. That comes from secondary sources and needs checking against the spec text (R1).

### Developer complaints and requests
| Source | What was said | Metric | Date | Link |
|---|---|---|---|---|
| better-auth issue #2685 | "FastAPI doesn't have great auth solution, FastAPI Users is the best in Python ecosystem but not as good as better-auth" | 5 reactions, 13 comments | 2025-05 | https://github.com/better-auth/better-auth/issues/2685 |
| better-auth issue #4352 | How to get the session in Python using the token | 4 reactions | 2025-09 | https://github.com/better-auth/better-auth/issues/4352 |
| fastapi-users discussion #1389 | How would you implement 2FA? (never answered) | 7 upvotes | 2024-05 | https://github.com/fastapi-users/fastapi-users/discussions/1389 |
| fastapi-users PR #1367 | Add a refresh-token implementation | 26 reactions | 2024-03 | https://github.com/fastapi-users/fastapi-users/pull/1367 |
| r/FastAPI | Looking for a modern all-in-one auth package; fastapi-users "is pretty complicated" | 15 points, 8 comments | 2026-04 | https://reddit.com/r/FastAPI/comments/1st5gsq/ |
| r/FastAPI | "I got tired of rebuilding OAuth for FastAPI projects" | 20 points | 2026-04 | https://reddit.com/r/FastAPI/comments/1sqplkf/ |
| r/FastAPI | Simple JWT auth for an MVP; a Django developer finds FastAPI auth basic | 18 points, 15 comments | 2026-05 | https://reddit.com/r/FastAPI/comments/1tstgn0/ |
| r/FastAPI | CRUDAuth launch: "tired of fixing auth bugs across all my deployed FastAPI apps" | 31 points | 2026-06 | https://reddit.com/r/FastAPI/comments/1u6m3uy/ |
| r/FastAPI | Handling RBAC in FastAPI | 37 points, 12 comments | 2025-10 | https://reddit.com/r/FastAPI/comments/1o845ia/ |
| r/FastAPI | React + FastAPI auth: best pattern, HTTP-only cookies? | 8 points, 9 comments | 2025-11 | https://reddit.com/r/FastAPI/comments/1ovbsnl/ |
| r/FastAPI | Better Auth integration with FastAPI (a JWKS bridge) | 3 points | 2026-05 | https://reddit.com/r/FastAPI/comments/1tggnes/ |
| HN comment | "Clerk, Betterauth and others mostly skip Django" | in a 193-point thread | 2025-05 | https://news.ycombinator.com/item?id=44125632 |

### Download proxies (last 30 days, pypistats, 2026-10-03)
| Package | Downloads | Note |
|---|---|---|
| fastapi | 357.8M | for scale |
| pyjwt | 530.9M | |
| authlib | 103.4M | mostly pulled in by other packages |
| passlib | 30.5M | |
| pyotp | 30.2M | |
| webauthn | 6.45M | |
| django-allauth | 4.76M | |
| fastapi-users | 1.27M | maintenance mode |
| fastapi-sso | 5.6M | |
| authx | 34K | |
| crudauth | 8.2K | |
| better-auth-server | 530 | |

For scale on the TypeScript side: Better Auth gets about 12.0M npm downloads a week.

## Competitors (what you are up against)
| Project | Traction | Overlap | How GotAuth differs |
|---|---|---|---|
| **fastapi-users** | 6,247 stars; 1.27M/month; maintenance mode | FastAPI auth: register, verify, reset, social, JWT/DB strategies | GotAuth is active, with 2FA, passkeys, orgs, API keys, the OAuth server, and an importer |
| **reauth** (fastapi-users author) | 11 stars; 13K/month; early | Email OTP, TOTP/HOTP, social, MFA flows, sessions. No passwords, passkeys, framework wrappers or OIDC server yet | GotAuth is a full stack plus the agent and MCP features. **The main brand risk** |
| **better-auth-server** (oumarbarry/better-auth-py) | 3 stars; 530/month; v1.1.0 on 2026-09-30 | Claims full parity with Better Auth TS 1.7.6: 27 plugins, 36 providers, SQLAlchemy, four frameworks. AI-assisted; the claims are unverified | GotAuth is Pythonic, tested in public, and not tied to Better Auth's release cadence |
| **qulf** | 2 stars; not on PyPI | "Inspired by Better-Auth"; four frameworks; four ORMs | Early. GotAuth wins on the agent and MCP features and docs for coding agents |
| **auth101**, **userharbor** | 6 and 15 stars | Narrow scope | Small |
| **AuthX** | 1,203 stars; 34K/month | JWT, CSRF and refresh tokens for FastAPI; no user storage | A token toolkit, not full auth |
| **SuperTokens**, **Ory**, **Keycloak** | Large | Full auth | Separate services to run. GotAuth is a library inside your app |
| **Auth0, Clerk, WorkOS, Stytch, Supabase** | Large | Hosted auth with Python SDKs | Per-MAU and per-connection pricing; your data lives outside your database |
| **django-allauth** | 10.4K stars; 4.76M/month | Django auth with a headless mode, MFA, passkeys and an OIDC provider | Django only. GotAuth does not compete there |

## What this means for GotAuth
1. **Lead with the agent and MCP gap, not with "Better Auth for Python".**
   - Other projects already use the port pitch, and its demand signal is weak (Better Auth's Python issues have 5 or fewer reactions).
   - The MCP authorization gap is stated in the SDKs' own docs.
2. **Be the obvious replacement for fastapi-users anyway.** About 1.27M monthly installs have no feature roadmap. `gotauth import fastapi-users` is the second marketing channel.
3. **Win on trust.** Auth bugs are severe, and even Better Auth had a public OAuth-state/magic-link advisory proof of concept on 2026-10-02. Publish:
   - the threat model
   - test results
   - OpenID conformance runs
   - signed releases
4. **Be the default for coding agents.** Agents currently write Python auth by hand. Ship `llms.txt`, a skill and short quickstarts, and prove it with the agent-install test.
5. **Keep the kill switch.** The demand is quiet. The Phase 0 demand test and the post-launch test exist so you stop early if the signal doesn't come.

## How developers describe the problem (for copy and search)
- "FastAPI doesn't have a great auth solution"
- "rebuilding OAuth for every FastAPI project"
- "tired of fixing auth bugs"
- all-in-one auth package for FastAPI
- fastapi-users alternative / fastapi-users maintenance mode
- JWT with passlib and python-jose
- HTTP-only cookies with React + FastAPI
- RBAC in FastAPI
- 2FA in FastAPI
- MCP server authentication / OAuth for MCP / MCP auth without Auth0
- API keys for my FastAPI app / API keys for agents
