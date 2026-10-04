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
| G9 MCP auth demand | >= 50 combined reactions on Python MCP auth requests (FastMCP, python-sdk) in 12 months, or one HN story on MCP auth with >= 50 points. Marginal: 25-49 reactions | **Pass** | 105 reactions on auth issues (56 on feature requests alone); HN "Zero-Touch OAuth for MCP", 278 points. Spread thin: the largest single request has 10. See the [MCP auth addendum](#mcp-auth-addendum-2026-10-03) |

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

## MCP auth addendum (2026-10-03)
> **Work package R1.** Everything below was retrieved on 2026-10-03 (UTC) unless a row says otherwise. Links were checked on 2026-10-04.
>
> **Sources:** the GitHub REST and GraphQL APIs (through an authenticated `gh`), the Hacker News Algolia API, PyPI JSON, pypistats, OSV, the IETF datatracker API, modelcontextprotocol.io and the MCP spec repository, and project docs.
>
> **Raw snapshots:** [`raw/`](raw/).
> - GitHub search, run, tree, repo and release responses and PyPI JSON are trimmed to the fields used here. Issue bodies and file contents are dropped.
> - Everything else keeps the full response.
> - All files are re-encoded as pretty-printed, ASCII-only JSON (non-ASCII characters as `\uXXXX` escapes). The data is unchanged.
> - The MCP spec text is not copied; it is cited by commit instead.
>
> **Reddit:** not covered. `www.reddit.com` returned 403 to both the JSON search and the HTML page. The PullPush archive used for r/FastAPI above returned 429 with a message that it does not offer free scraping to agents ([raw/pullpush-r-mcp-auth-429.json](raw/pullpush-r-mcp-auth-429.json)), so it was not retried. r/mcp evidence is therefore missing from G9.

### Corrections and updates to the sections above
1. **CIMD claim (section "The MCP authorization gap").** The spec text confirms it, with a nuance:
   - CIMD has been a **SHOULD** for authorization servers since revision 2025-11-25 ([2025-11-25 text](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)).
   - Revision 2026-07-28 **deprecates** dynamic client registration in favor of CIMD ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog), PR [#2858](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2858)).
   - Details are in [MCP authorization spec 2026-07-28](#2-mcp-authorization-spec-revision-2026-07-28).
2. **MCP Python SDK quote.** The line "You don't write this. It's your identity provider." now lives on the SDK's authorization docs page, not in the README: [py.sdk.modelcontextprotocol.io/run/authorization](https://py.sdk.modelcontextprotocol.io/run/authorization/). The same page covers identity assertion (SEP-990, enterprise-managed authorization) on both client and server.
3. **FastMCP built-in providers are not all hosted.**
   - Keycloak is self-hosted ([FastMCP Keycloak guide](https://gofastmcp.com/integrations/keycloak)), and Supabase can be self-hosted.
   - The accurate statement: none of the built-in providers keeps users in your app's database. Each one hands sign-in to a separate identity provider ([authentication overview](https://gofastmcp.com/servers/auth/authentication)).
   - FastMCP accepts CIMD clients by default in `OAuthProxy` (`enable_cimd=True`, [OAuth proxy docs](https://gofastmcp.com/servers/auth/oauth-proxy#cimd-support)). Client-side CIMD arrived in 3.0.0 ([client CIMD docs](https://gofastmcp.com/clients/auth/cimd)).
   - Current version 4.0.10 (2026-09-25); repository [PrefectHQ/fastmcp](https://github.com/PrefectHQ/fastmcp), as listed in the [PyPI project URLs](https://pypi.org/pypi/fastmcp/json); 27,962 stars; 50.1M downloads in the last month ([pypistats](https://pypistats.org/api/packages/fastmcp/recent)).
4. **"No mature embeddable Python option" needs two qualifiers.**
   - django-allauth's OpenID Connect provider added DCR in 65.18.0 and CIMD in 65.19.0 ([CIMD docs](https://docs.allauth.org/en/latest/idp/openid-connect/client-id-metadata-document.html), [release notes](https://docs.allauth.org/en/latest/release-notes/recent.html)). It is Django-only and has no RFC 9728 resource-side helper.
   - better-auth-server ships an OAuth 2.1 authorization server plugin with RFC 8707 resources and DCR, but its source says CIMD is not ported ([register.py at d2826ca](https://github.com/oumarbarry/better-auth-py/blob/d2826ca2e05ecfa8c15ff22bae9430e4807a460f/src/better_auth/plugins_ext/oauth_provider/register.py#L568)).
   - The gap that remains: an embeddable, framework-agnostic Python authorization server with CIMD, built on your own user table, for FastAPI and ASGI apps.
5. **Hosted pricing used in the build plan's "Why not X?" table** (checked on the vendors' pricing pages):
   - Clerk's basic organizations are free on every plan. The $100/mo figure is the optional "Enhanced B2B" add-on ([clerk.com/pricing](https://clerk.com/pricing)).
   - Per-connection SSO prices: Clerk $75/mo each for connections 2-15, with 1 included on Pro ([pricing](https://clerk.com/pricing)). WorkOS $125/mo each for 1-15, falling to $65 at 51-100 ([pricing](https://workos.com/pricing)). Auth0 B2B $100/mo per connection after the 3 or 5 included ([pricing](https://auth0.com/pricing)).
   - Auth0's "AI Agents" add-on adds 50% to the base plan price, but "Auth for MCP" is listed as included on every plan, Free included ([pricing](https://auth0.com/pricing)). The page renders differently across fetches, so check it in a browser before quoting it publicly.
   - All three hosted services now document MCP authorization with CIMD: [Auth0](https://auth0.com/docs/get-started/auth0-overview/create-applications/register-applications-with-cimd) (an admin imports each client URL first), [Clerk](https://clerk.com/changelog/2026-09-17-client-id-metadata-documents-ga) (general availability, September 2026), [WorkOS](https://workos.com/docs/authkit/mcp) (off by default, switched on in the dashboard).
   - The build plan text is outside R1's write scope; see [requests/R1-build-plan-updates.md](../requests/R1-build-plan-updates.md).
6. **better-auth-server "AI-assisted".** Confirmed by commit trailers: 47 of its 56 commits carry a `Co-Authored-By` trailer naming an AI model, and all 56 come from one account ([commit list](https://github.com/oumarbarry/better-auth-py/commits/main), [contributors](https://github.com/oumarbarry/better-auth-py/graphs/contributors)). This says nothing about quality by itself; it is why the parity claim needs independent checks (section 4 below).
7. **New small MCP authorization server projects** found through HN in the last 12 months:
   - [crumrine/fastmcp-personal-auth](https://github.com/crumrine/fastmcp-personal-auth): Python, MIT, 3 stars, OAuth 2.1 for personal FastMCP servers without an external identity provider.
   - [AuthPlane/authserver](https://github.com/AuthPlane/authserver): Go, AGPL-3.0, 78 stars, a standalone OAuth 2.1 server for MCP.
   - Neither is an embeddable library on an app's own user table.

### 1. MCP auth demand (gate G9)
**Repository check.**
- FastMCP's repository is `PrefectHQ/fastmcp` per its [PyPI project URLs](https://pypi.org/pypi/fastmcp/json) (raw: [pypi-fastmcp.json](raw/pypi-fastmcp.json)).
- `modelcontextprotocol/python-sdk` has GitHub Discussions turned off (`has_discussions: false` from `GET /repos/modelcontextprotocol/python-sdk`), so it has issues only.

**Exact queries** (window: created on or after 2025-10-03):

| Source | Query | Raw file |
|---|---|---|
| GitHub issues | `GET https://api.github.com/search/issues?q=repo:<repo>+is:issue+<term>+created:>=2025-10-03&sort=reactions&order=desc&per_page=100` for `<repo>` in `PrefectHQ/fastmcp`, `modelcontextprotocol/python-sdk` and `<term>` in `auth`, `oauth`, `authentication`, `authorization` | `raw/gh-issues-<repo>-<term>.json` |
| GitHub issues, all time (context only) | same, `q=repo:<repo>+is:issue+auth+OR+oauth+OR+authentication+OR+authorization`, `per_page=50` | `raw/gh-issues-<repo>-alltime.json` |
| GitHub discussions | `gh api graphql`: `search(query: "repo:<repo> <term> created:>=2025-10-03", type: DISCUSSION, first: 100)` for `<term>` in `auth`, `oauth` | `raw/gh-discussions-<repo>-<term>.json` |
| Hacker News | `https://hn.algolia.com/api/v1/search?query=<q>&tags=story&hitsPerPage=100&attributesToRetrieve=title,url,points,num_comments,created_at,author&attributesToHighlight=[]` for `<q>` in "MCP auth", "MCP OAuth", "FastMCP auth", "MCP authorization", "MCP authentication"; the 12-month files add `&numericFilters=created_at_i>1759449600` | `raw/hn-<q>.json`, `raw/hn-<q>-12m.json` |
| r/mcp | `https://www.reddit.com/r/mcp/search.json?q=auth&restrict_sr=1&sort=top&t=year&limit=100` (403); `https://api.pullpush.io/reddit/search/submission/?subreddit=mcp&q=auth&size=100&after=1759449600&sort_type=score&sort=desc` (429) | `raw/pullpush-r-mcp-auth-429.json` |

**Counting rule.**
- Take the union of the four keyword searches per repository and drop duplicates. That gives 225 FastMCP issues and 140 python-sdk issues.
- Keep the issues whose title is about authentication or authorization: providers, OAuth flows, tokens, scopes, consent, discovery metadata, CIMD/DCR.
- Split them by hand into **requests** (features, docs) and **bugs**.
- Reactions are `reactions.total_count` from the search API.
- Issue numbers counted:
  - FastMCP requests (40): #4252, #2097, #4334, #2377, #2810, #2863, #3291, #3619, #1996, #2346, #2499, #2634, #2103, #3150, #4190, #4588.
  - FastMCP bugs (34): #4513, #2027, #2077, #2401, #2628, #3598, #4265, #2123, #2197, #2302, #2461, #2530, #2641, #2643, #3037, #3425, #3427, #3574, #3635, #3866, #3996, #4054, #4098, #4390, #4467, #4789.
  - python-sdk requests (16): #1593, #1743, #1581, #1723, #1724, #2024.
  - python-sdk bugs (15): #3103, #1919, #3505, #3508, #1523, #1664, #2270, #2776, #3545.
- Left out as not about auth: for example python-sdk [#1798](https://github.com/modelcontextprotocol/python-sdk/issues/1798) (DNS-rebinding host header guide, 23 reactions), [#2806](https://github.com/modelcontextprotocol/python-sdk/issues/2806) (tasks extension) and FastMCP [#5016](https://github.com/PrefectHQ/fastmcp/issues/5016) (skills extension).

**Result.**

| Count | FastMCP | python-sdk | Total | Threshold |
|---|---|---|---|---|
| Reactions on auth issues (requests + bugs) | 74 | 31 | **105** | >= 50: pass |
| Reactions on auth feature requests only | 40 | 16 | **56** | >= 50: pass |
| Largest single auth request | 9 (#4252) | 10 (#1593) | 10 | |
| HN story on MCP auth, 12 months | | | **278 points** | >= 50: pass |

**G9: Pass**, on both arms. Read it with care:
- The demand is spread over many small issues. No single Python MCP auth request reaches 25 reactions.
- Most issues are integration pain with `OAuthProxy` and hosted identity providers. None asks outright for "an authorization server on my own user table".
- The closest signals are a customizable consent page ([#2097](https://github.com/PrefectHQ/fastmcp/issues/2097)), scope selection on the consent screen ([#2377](https://github.com/PrefectHQ/fastmcp/issues/2377)), reusable OAuth flow components ([python-sdk #1743](https://github.com/modelcontextprotocol/python-sdk/issues/1743)), and questions about durable OAuth state and sharing auth across deployments (discussions below).
- The 278-point HN story is about enterprise-managed authorization (identity-provider-driven login for MCP), not about Python or embeddable servers.

**Evidence rows: GitHub issues** (12 months, 2 or more reactions, plus two zero-reaction rows for context)

| Repo | Issue | Type | Created | State | Reactions | Comments |
|---|---|---|---|---|---|---|
| python-sdk | [#1593 Implement SEP-990: Enterprise Managed Authorization](https://github.com/modelcontextprotocol/python-sdk/issues/1593) | request | 2025-11-07 | closed | 10 | 4 |
| FastMCP | [#4252 Let OAuthProxy issue FastMCP JWTs that outlive the upstream token](https://github.com/PrefectHQ/fastmcp/issues/4252) | request | 2026-05-29 | closed | 9 | 2 |
| FastMCP | [#2097 Customizable consent page](https://github.com/PrefectHQ/fastmcp/issues/2097) | request | 2025-10-15 | closed | 6 | 3 |
| FastMCP | [#4334 Custom responses when tool-level scope validation fails](https://github.com/PrefectHQ/fastmcp/issues/4334) | request | 2026-06-19 | open | 6 | 1 |
| python-sdk | [#3103 RequireAuthMiddleware omits RFC 6750 scope in WWW-Authenticate](https://github.com/modelcontextprotocol/python-sdk/issues/3103) | bug | 2026-07-16 | open | 4 | 2 |
| FastMCP | [#2377 Scope selection in the OAuth consent screen](https://github.com/PrefectHQ/fastmcp/issues/2377) | request | 2025-11-05 | open | 3 | 4 |
| FastMCP | [#4513 401 challenge omits scope when required_scopes is set](https://github.com/PrefectHQ/fastmcp/issues/4513) | bug | 2026-07-16 | closed | 3 | 1 |
| FastMCP | [#2027 OAuth proxy MCP server not calling /register](https://github.com/PrefectHQ/fastmcp/issues/2027) | bug | 2025-10-08 | closed | 2 | 10 |
| FastMCP | [#2077 Root protected-resource metadata 404, path form 200](https://github.com/PrefectHQ/fastmcp/issues/2077) | bug | 2025-10-12 | closed | 2 | 4 |
| FastMCP | [#2401 GoogleProvider not working with Claude Desktop](https://github.com/PrefectHQ/fastmcp/issues/2401) | bug | 2025-11-08 | closed | 2 | 8 |
| FastMCP | [#2628 Re-authentication occasionally required](https://github.com/PrefectHQ/fastmcp/issues/2628) | bug | 2025-12-15 | closed | 2 | 15 |
| FastMCP | [#2810 Option to not forward the resource parameter](https://github.com/PrefectHQ/fastmcp/issues/2810) | request | 2026-01-07 | closed | 2 | 3 |
| FastMCP | [#2863 Support CIMD (SEP-991)](https://github.com/PrefectHQ/fastmcp/issues/2863) | request | 2026-01-13 | closed | 2 | 1 |
| FastMCP | [#3291 Optional OAuth: allow unauthenticated access](https://github.com/PrefectHQ/fastmcp/issues/3291) | request | 2026-02-25 | closed | 2 | 2 |
| FastMCP | [#3598 CIMD redirect_uri should accept any loopback port (RFC 8252)](https://github.com/PrefectHQ/fastmcp/issues/3598) | bug | 2026-03-23 | closed | 2 | 2 |
| FastMCP | [#3619 Structured auth failure reasons in 401 responses](https://github.com/PrefectHQ/fastmcp/issues/3619) | request | 2026-03-25 | open | 2 | 1 |
| FastMCP | [#4265 OAuthProxy refresh-token rotation has no grace window](https://github.com/PrefectHQ/fastmcp/issues/4265) | bug | 2026-06-02 | open | 2 | 12 |
| python-sdk | [#1743 Extract OAuth flow logic into reusable components](https://github.com/modelcontextprotocol/python-sdk/issues/1743) | request | 2025-12-05 | open | 2 | 9 |
| python-sdk | [#1919 Trailing slash in the metadata issuer breaks clients](https://github.com/modelcontextprotocol/python-sdk/issues/1919) | bug | 2026-01-21 | open | 2 | 5 |
| python-sdk | [#3505 Authorization URL built with a second "?"](https://github.com/modelcontextprotocol/python-sdk/issues/3505) | bug | 2026-09-15 | open | 2 | 4 |
| python-sdk | [#3508 Revocation requires client_secret to be present](https://github.com/modelcontextprotocol/python-sdk/issues/3508) | bug | 2026-09-15 | open | 2 | 3 |
| python-sdk | [#1801 Server-side CIMD support](https://github.com/modelcontextprotocol/python-sdk/issues/1801) | request | 2025-12-18 | open | 0 | 4 |
| python-sdk | [#3283 Authentication in the high-level MCPServer](https://github.com/modelcontextprotocol/python-sdk/issues/3283) | request | 2026-08-11 | open | 0 | 3 |

For scale, the all-time top auth requests are older and bigger: FastMCP [#825 Full OAuth 2.1 authorization for FastMCP servers](https://github.com/PrefectHQ/fastmcp/issues/825) (22 reactions, 2025-06-13), [#1918 Keycloak provider with DCR](https://github.com/PrefectHQ/fastmcp/issues/1918) (19, 2025-09-25) and python-sdk [#618 Remote MCP OAuth example](https://github.com/modelcontextprotocol/python-sdk/issues/618) (12, 2025-05-02). All three fall outside the 12-month window (raw: `gh-issues-*-alltime.json`).

**Evidence rows: FastMCP discussions** (12 months; 25 match "auth" and 15 match "oauth"; upvotes are not counted in G9)

| Discussion | Created | Upvotes | Comments | Answered |
|---|---|---|---|---|
| [#4591 Compatibility with the 2026-07-28 MCP spec RC](https://github.com/PrefectHQ/fastmcp/discussions/4591) | 2026-07-21 | 4 | 3 | no |
| [#3096 Does the OAuth/OIDC proxy avoid token passthrough?](https://github.com/PrefectHQ/fastmcp/discussions/3096) | 2026-02-06 | 3 | 1 | yes |
| [#2463 OIDCProxy with IntrospectionVerifier: getting the id_token](https://github.com/PrefectHQ/fastmcp/discussions/2463) | 2025-11-20 | 3 | 3 | no |
| [#4086 Should durable OAuth state use an ACID store?](https://github.com/PrefectHQ/fastmcp/discussions/4086) | 2026-04-30 | 1 | 2 | no |
| [#4249 Share auth across multiple MCP server deployments?](https://github.com/PrefectHQ/fastmcp/discussions/4249) | 2026-05-27 | 1 | 2 | no |
| [#4277 RemoteAuthProvider with Auth0](https://github.com/PrefectHQ/fastmcp/discussions/4277) | 2026-06-03 | 1 | 3 | no |
| [#3564 OAuthProxy + Auth0 + Cursor](https://github.com/PrefectHQ/fastmcp/discussions/3564) | 2026-03-20 | 1 | 1 | yes |

**Evidence rows: Hacker News** (stories from the five queries, deduplicated)

| Story | Points | Comments | Date | On topic? |
|---|---|---|---|---|
| [Zero-Touch OAuth for MCP](https://news.ycombinator.com/item?id=48592163) (links to the [MCP blog on enterprise-managed auth](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)) | 278 | 103 | 2026-06-18 | yes, counts for G9 |
| [Show HN: Kontext CLI, credential broker for AI coding agents](https://news.ycombinator.com/item?id=47765374) | 70 | 17 | 2026-04-14 | adjacent (agent credentials, Go) |
| [Show HN: HyprMCP, analytics, logs and auth for MCP servers](https://news.ycombinator.com/item?id=45521788) | 59 | 8 | 2025-10-08 | partly (TypeScript gateway) |
| [Show HN: Metorial, "Vercel for MCP"](https://news.ycombinator.com/item?id=45580771) | 59 | 25 | 2025-10-14 | no (hosting; auth is a side feature) |
| [Show HN: Mcptunnels, ngrok for MCP with basic OAuth](https://news.ycombinator.com/item?id=49527807) | 15 | 4 | 2026-09-01 | partly |
| [Show HN: mcp-use v2, rebuilt for the stateless 2026-07-28 spec](https://news.ycombinator.com/item?id=49198472) | 10 | 1 | 2026-08-06 | adjacent |
| [Show HN: AuthPlane, OAuth 2.1 and PKCE authorization server for MCP](https://news.ycombinator.com/item?id=48573884) | 7 | 1 | 2026-06-17 | yes (Go) |
| [Personal MCP server on every Claude platform without Auth0](https://news.ycombinator.com/item?id=47318803) | 2 | 1 | 2026-03-10 | yes (Python, FastMCP) |
| [Supabase Auth and FastMCP example](https://news.ycombinator.com/item?id=47910232) | 2 | 1 | 2026-04-26 | yes (Python) |
| Outside the window: [From MCP to shell: MCP auth flaws enable RCE](https://news.ycombinator.com/item?id=45348183) | 148 | 40 | 2025-09-23 | yes |
| Outside the window: [Building Supabase-like OAuth authentication for MCP servers](https://news.ycombinator.com/item?id=45126950) | 34 | 3 | 2025-09-04 | yes |

The query "FastMCP auth" returns no story above 5 points. Python-specific MCP auth stories stay in single digits, matching G6.

### 2. MCP authorization spec, revision 2026-07-28
**Revision check.**
- **It exists and is the latest.** `https://modelcontextprotocol.io/specification/latest` redirects to `/specification/2026-07-28`.
- The spec repository's `docs/specification/` holds `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, `2026-07-28` and `draft`.
- The revision was added in commit [b488c16](https://github.com/modelcontextprotocol/modelcontextprotocol/commit/b488c16623) on 2026-07-28. The text read here is at [db4bfcf](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/db4bfcff3d60f5df01a21bdf6b78f7012cac4634/docs/specification/2026-07-28/basic/authorization).
- **Authorization is now four pages:**
  - [overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  - [authorization server discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
  - [client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)
  - [security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- **Draft versions it cites:** CIMD `draft-ietf-oauth-client-id-metadata-document-00` and OAuth 2.1 `draft-ietf-oauth-v2-1-13`. The current IETF revisions are CIMD **-02** (2026-07-06) and OAuth 2.1 **-16** (2026-09-03), per [datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) (raw: `ietf-*.json`).
- **Auth changes in 2026-07-28** ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)):
  - DCR deprecated (PR #2858)
  - RFC 9207 `iss` in authorization responses: SHOULD for servers, and clients validate it (SEP-2468)
  - `application_type` required in DCR requests (SEP-837)
  - client credentials bound to the issuing authorization server (SEP-2352)
- **The rest of the revision** makes the protocol stateless (no `initialize`, no `Mcp-Session-Id`). That matters to O2's FastMCP and SDK versions, not to O1.

**Requirement levels** (AS = authorization server; quotes under 15 words, the rest paraphrased)

| Topic | Level | What the spec says | Section |
|---|---|---|---|
| CIMD | AS and clients **SHOULD** | "Authorization servers and MCP clients **SHOULD** support OAuth Client ID Metadata Documents" | [overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#overview), [CIMD](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#client-id-metadata-documents) |
| CIMD, AS duties | MUST / SHOULD | **SHOULD** fetch documents for URL client ids and cache by HTTP headers. **MUST** check the document's `client_id` equals the URL, validate redirect URIs against it, and check it is valid JSON with the required fields (`client_id`, `client_name`, `redirect_uris`). Client id URLs **MUST** be https with a path | [implementation requirements](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#implementation-requirements) |
| CIMD advertising | (defined) | AS metadata carries `client_id_metadata_document_supported: true`; clients check it | [advertising CIMD support](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#advertising-cimd-support) |
| CIMD client auth | client **MAY** | Clients may use `private_key_jwt` at the token endpoint | [implementation requirements](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#implementation-requirements) |
| Dynamic client registration | **MAY**, deprecated | "Dynamic Client Registration is deprecated." Kept for older servers | [DCR](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#dynamic-client-registration) |
| Pre-registration | clients **SHOULD** | Clients should accept static client credentials; preferred first when available | [pre-registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#pre-registration) |
| RFC 9728 protected resource metadata | MCP servers **MUST** | "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata". The document lists at least one `authorization_servers` entry. Servers use the `WWW-Authenticate` `resource_metadata` parameter or a well-known URI (path form or root); clients support both | [overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#overview), [AS location](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#authorization-server-location), [discovery requirements](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#protected-resource-metadata-discovery-requirements) |
| AS metadata | AS **MUST** offer RFC 8414 or OIDC discovery | For an issuer with a path, clients try RFC 8414 path insertion, then OIDC path insertion, then OIDC path appending. The `issuer` in the document **MUST** equal the issuer used to build the URL | [AS metadata discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#authorization-server-metadata-discovery) |
| RFC 8707 resource indicators | clients **MUST** | The `resource` parameter "**MUST** be included in both authorization requests and token requests." It names the server's canonical URI. Servers should accept uppercase scheme and host; prefer no trailing slash | [resource parameter](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation), [canonical URI](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#canonical-server-uri) |
| PKCE | clients **MUST**, S256 | Clients **MUST** use PKCE with `S256` when capable, and refuse to proceed if `code_challenge_methods_supported` is absent. An AS offering OIDC discovery "**MUST** include `code_challenge_methods_supported` in their metadata" | [authorization code protection](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#authorization-code-protection) |
| Scopes in 401 | MCP servers **SHOULD** | Include `scope` in the `WWW-Authenticate` challenge; clients treat it as authoritative | [scope selection strategy](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#scope-selection-strategy) |
| Step-up (403) | MCP servers **SHOULD** | Answer 403 with `error="insufficient_scope"`, `scope`, `resource_metadata` and an optional `error_description`. Put every scope the operation needs in one challenge. Clients re-authorize with the union of old and new scopes. "Servers **MUST** account for scope hierarchies" | [runtime insufficient scope](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#runtime-insufficient-scope-errors), [step-up flow](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#step-up-authorization-flow) |
| Token audience | MCP servers **MUST** | Accept only tokens issued for them (RFC 8707 audience); invalid or expired tokens get 401; no token passthrough | [token handling](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#token-handling), [privilege restriction](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction) |
| Redirect URIs | AS **MUST** | "All redirect URIs **MUST** be either `localhost` or use HTTPS." Exact match against registered values. All AS endpoints over HTTPS | [communication security](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#communication-security), [open redirection](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#open-redirection) |
| Loopback redirects with CIMD | AS **MUST** / **SHOULD** | AS **MUST** clearly show the redirect URI hostname during authorization, **SHOULD** warn on localhost-only redirect URIs, **MAY** require attestation | [localhost redirect URI risks](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#localhost-redirect-uri-risks) |
| `iss` in responses (RFC 9207) | AS **SHOULD** | Send `iss` on success and error responses. Servers that send it **MUST** set `authorization_response_iss_parameter_supported: true`. Expected to become MUST | [authorization response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) |
| Refresh tokens | AS **MUST** rotate for public clients | Short-lived access tokens **SHOULD**. Clients **MAY** request `offline_access`. MCP servers **SHOULD NOT** list `offline_access` in `scopes_supported` or challenges | [token theft](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#token-theft), [refresh tokens](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#refresh-tokens) |
| SSRF on CIMD fetch | AS **SHOULD** consider | Points to CIMD draft section 6. Domain trust policies **MAY** be used | [AS abuse protection](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#authorization-server-abuse-protection), [trust policies](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#trust-policies) |

**Comparison with CONTRACTS 12.2-12.4, O1 and O2**

| Topic | GotAuth plan | Spec 2026-07-28 | Result |
|---|---|---|---|
| CIMD on by default, required for `mcp=True` | O1 `allow_cimd=True`; 12.3 CIMD rules | SHOULD | matches |
| CIMD URL and document checks | https, no fragment or userinfo, `client_id` == URL, SSRF guard, 64 KB, 5s | also requires a path component and the required fields; draft -02 adds no dot segments, no secrets or symmetric auth methods in the document, no caching of errors, about 5 KB | **differs**: request item 4 |
| CIMD client auth | auth `none` only | clients MAY use `private_key_jwt` | **clarify**: request item 4 |
| DCR | off by default, public clients | MAY, deprecated | matches; request item 1 (metadata) |
| Discovery metadata fields | "CIMD support" and `code_challenge_methods_supported` | exact field names; OIDC discovery MUST carry PKCE methods; `authorization_response_iss_parameter_supported` when `iss` is sent | **differs**: request item 1 |
| `iss` in authorization responses | O1: `iss` in "the response" | SHOULD on success and error | **clarify**: request item 2 |
| Redirect URIs | exact match, loopback any port | localhost or https only; exact match | **clarify**: request item 3 |
| Consent screen | client name, CIMD host, scopes | MUST show the redirect URI hostname; SHOULD warn on localhost-only | **differs**: request item 5 |
| Resource indicators | `resource` at authorize, bound to `aud` | clients send `resource` at authorize **and** token requests, refresh included | **differs**: request item 6 |
| Issuer and path insertion | RFC 8414 at the host root plus OIDC inside the mount | matches the client discovery order; `issuer` must match exactly | matches; request item 7 adds a test |
| HTTPS | not stated | all AS endpoints MUST be HTTPS | **differs**: request item 8 |
| Refresh rotation | rotated on every use, reuse revokes the family | MUST rotate for public clients | matches |
| Short-lived access tokens | 10 minutes | SHOULD be short-lived | matches |
| Token claims and audience (12.2) | `aud` = resource or issuer; RFC 9068 `at+jwt` | MCP servers MUST check audience | matches (O2 checks `aud` contains `resource`) |
| Revocation (12.2) | in-process immediate; remote JWT-only until expiry; RFC 7662 opt-in | no revocation requirement | matches |
| 401 challenge (12.4, O2) | `resource_metadata` | SHOULD add `scope` | **differs**: request item 9 |
| 403 challenge (O2) | `insufficient_scope` + `scope` | SHOULD add `resource_metadata` | **differs**: request item 9 |
| Protected resource metadata (12.4) | `resource`, `authorization_servers`, `scopes_supported`, `bearer_methods_supported` | SHOULD NOT list `offline_access` | **clarify**: request item 9 |
| Scope hierarchy | `has_scopes` is an exact match | MUST account for hierarchies where they exist | **clarify**: request item 10 |

All of these are written up as exact changes in [requests/R1-o1-mcp-spec.md](../requests/R1-o1-mcp-spec.md). None of them changes a 12.5 cross-plugin shape.

### 3. Hero-clip facts (agent split screen)
| Package | Latest version | Uploaded | Notes | Sources |
|---|---|---|---|---|
| passlib | 1.7.4 | 2020-10-08 | No release in almost 6 years. Its bcrypt backend reads `bcrypt.__about__`, which is gone since bcrypt 4.1.1; the error report [pyca/bcrypt#684](https://github.com/pyca/bcrypt/issues/684) is still open (111 reactions). A fork, [libpass](https://pypi.org/project/libpass/), is at 1.9.3 (2025-10-09). 30.5M downloads last month | [PyPI JSON](https://pypi.org/pypi/passlib/json), [pypistats](https://pypistats.org/api/packages/passlib/recent) |
| python-jose | 3.5.0 | 2025-05-28 | No release from 3.3.0 (2021-06-05) until 3.4.0 (2025-02-18). CVE-2024-33663 (algorithm confusion) and CVE-2024-33664 (JWE decompression bomb) were published 2024-04-26 and fixed only in 3.4.0. Last commit on the default branch: 2025-05-28. 30.7M downloads last month | [PyPI JSON](https://pypi.org/pypi/python-jose/json), [OSV](https://osv.dev/list?ecosystem=PyPI&q=python-jose), [GHSA-6c5p-j8vq-pqhj](https://github.com/advisories/GHSA-6c5p-j8vq-pqhj), [GHSA-cjwg-qfpm-7377](https://github.com/advisories/GHSA-cjwg-qfpm-7377) |
| PyJWT | 2.15.1 | 2026-09-28 | Actively released; 530.9M downloads last month | [PyPI JSON](https://pypi.org/pypi/pyjwt/json) |
| pwdlib | 0.3.1 | 2026-08-12 | Repository [frankie567/pwdlib](https://github.com/frankie567/pwdlib), the fastapi-users author's account; 3.3M downloads last month | [PyPI JSON](https://pypi.org/pypi/pwdlib/json) |

**FastAPI's security tutorial** ([OAuth2 with password hashing and JWT](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/), checked 2026-10-03):
- **JWT:** it recommends **PyJWT**, installed with `uv add pyjwt` (`pyjwt[crypto]` for RSA or ECDSA).
- **Hashing:** it recommends **pwdlib** with Argon2: "The recommended algorithm is 'Argon2'."
- **passlib:** mentioned only for reading old hashes from other systems.
- **History of the page** ([commits](https://github.com/fastapi/fastapi/commits/master/docs/en/docs/tutorial/security/oauth2-jwt.md)):
  - python-jose was replaced by PyJWT on 2024-05-20 ([#11589](https://github.com/fastapi/fastapi/pull/11589)).
  - passlib was replaced by pwdlib with Argon2 on 2025-09-29 ([#13917](https://github.com/fastapi/fastapi/pull/13917)).

**What the clip may say:**
- **Safe to say:** "The FastAPI docs moved off python-jose in May 2024 and off passlib in September 2025. In the Feb 2026 benchmark, agents still wrote passlib + python-jose." Benchmark: [Amplifying.ai report](https://amplifying.ai/research/claude-code-picks/report).
- **Do not say** "python-jose is unmaintained": it shipped releases in 2025.
- **Say instead:** it went almost four years without a release (June 2021 to February 2025); two CVEs published in April 2024 stayed unfixed until February 2025; its last release was May 2025.

### 4. Competitor detail: better-auth-server and reauth
| | better-auth-server | reauth |
|---|---|---|
| Repository | [oumarbarry/better-auth-py](https://github.com/oumarbarry/better-auth-py), created 2026-09-04 | [frankie567/reauth](https://github.com/frankie567/reauth), created 2026-05-09 |
| Stars, forks, open issues | 3, 0, 0 | 11, 4, 6 |
| License | MIT | MIT |
| Python | >= 3.10 | >= 3.14 |
| Latest release | [v1.1.0](https://github.com/oumarbarry/better-auth-py/releases/tag/v1.1.0), 2026-09-30; 6 server releases since 2026-09-04 | [v0.4.2](https://github.com/frankie567/reauth/releases/tag/v0.4.2), 2026-09-26; 17 releases since 2026-05-11 |
| Changelog notes | 1.1.0 tracks Better Auth TypeScript v1.7.6. It changes some defaults and adds tables or columns for some plugins, with an upgrade guide ([CHANGELOG](https://github.com/oumarbarry/better-auth-py/blob/main/CHANGELOG.md)) | 0.4.2 fixes TOTP/HOTP with non-ASCII input. 0.4.0 breaks the `PrivateKeyJWTOIDCFactor` API. 0.3.0 adds identity sessions and refresh tokens ([releases](https://github.com/frankie567/reauth/releases)) |
| README claims | Full parity with Better Auth TypeScript v1.7.6 (same routes, JSON shapes, error codes); 36 social providers; 27 plugins; FastAPI, Litestar, Flask and Django integrations; SQLAlchemy adapter ([server README](https://github.com/oumarbarry/better-auth-py/blob/main/src/better_auth/README.md)) | Early stage, unstable API. Roadmap done: email OTP, HOTP, TOTP, social login, MFA flows, sessions. Not yet: passwords, security keys, passkeys, framework and ORM wrappers, OIDC server, teams ([README](https://github.com/frankie567/reauth#roadmap)) |
| Claim check | **Verified:** 27 plugin classes in `plugins_ext.__all__`; 36 providers named in the README; an OAuth 2.1 server plugin with RFC 8707 resources and DCR.<br>**Stated by the project as not ported:** CIMD (source comments), SAML, SCIM.<br>**Unverified:** "full parity". Only one parity-named test file was found (`tests/providers/test_authorize_url_parity.py`) and no cross-run against the TypeScript library | **Verified:** the roadmap matches the docs ([getting started](https://frankie567.github.io/reauth/getting-started/)). There is no FastAPI integration or password factor yet |
| Tests | 2,626 test functions in 99 Python files under `tests/` (static count of `def test_` at d2826ca). The CI job for Python 3.14 ran **3,049 tests, all passed**, on 2026-09-30 ([run](https://github.com/oumarbarry/better-auth-py/actions/runs/36656784799)) | 177 test functions in 18 Python files under `tests/` (static count at 27a5529). CI ran **348 tests, all passed, 90% line coverage** on 2026-09-27 ([run](https://github.com/frankie567/reauth/actions/runs/36342362756)) |
| CI runs them? | Yes: `ci.yml` runs ruff, ty and pytest on Python 3.10-3.14 on pushes to main and on PRs ([workflow](https://github.com/oumarbarry/better-auth-py/blob/main/.github/workflows/ci.yml)) | Yes: `build.yml` runs lint, ty and pytest with coverage on every push and PR, on Python 3.14 only. Also CodeQL, OpenSSF Scorecard and dependency review ([workflows](https://github.com/frankie567/reauth/tree/main/.github/workflows)). Dependabot branch builds failed on 2026-10-03 |
| Security policy | No `SECURITY.md`; GitHub private vulnerability reporting is off. The README has a "Security notes" section on behavior | [SECURITY.md](https://github.com/frankie567/reauth/blob/main/SECURITY.md): private GitHub advisories, fixes for the latest release only, no response deadlines. Private vulnerability reporting is on. OpenSSF Baseline badge |
| Downloads (pypistats `last_month`) | 530 ([pypistats](https://pypistats.org/api/packages/better-auth-server/recent)) | 13,378 ([pypistats](https://pypistats.org/api/packages/reauth/recent)) |

**How to read it.**
- **better-auth-server is broad and well tested in CI.** Its risks are a 4-week-old project with one contributor, no security policy, and parity claims that no outside check confirms.
- **reauth is narrow and early, with the stronger security process.** It still lacks passwords and framework integrations. Python >= 3.14 limits who can adopt it today.
- **Competitor-watch triggers are unchanged:** neither repository is near 500 stars, and reauth has no password auth, FastAPI integration or 1.0.
