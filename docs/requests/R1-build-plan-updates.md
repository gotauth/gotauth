# R1 request: factual updates to build-plan.md

| | |
|---|---|
| From | R1 (validation addendum) |
| For | the owner or integrator (`docs/build-plan.md` is outside R1's write scope) |
| Date | 2026-10-04 (data retrieved 2026-10-03) |
| Evidence | [validation-research.md, MCP auth addendum](../research/validation-research.md#mcp-auth-addendum-2026-10-03) |

R1 checked the build plan's public-facing claims against current sources. Five need a small edit before they reach a landing page or a post. The rest held up.

## 1. Add G9 to the validation gate table
**Why:** R1 adds gate G9 and its result.

```diff
 | G8 differentiation | A written "why not X" | Met (above), refined by R1 |
+| G9 MCP auth demand | >= 50 reactions on Python MCP auth requests (FastMCP, python-sdk) in 12 months, or one HN story on MCP auth with >= 50 points | Pass (105 reactions, 56 on requests; HN 278 points), spread thin: largest single request 10 |
```

## 2. "Why now", third bullet: FastMCP providers
**Why:**
- Keycloak is a self-hosted FastMCP provider ([guide](https://gofastmcp.com/integrations/keycloak)), so "every built-in provider is a hosted service" is not accurate.
- What holds: every built-in provider sends sign-in to a separate identity provider, and none uses the app's own user table ([authentication overview](https://gofastmcp.com/servers/auth/authentication)).
- The SDK quote now lives on the SDK's docs site ([authorization page](https://py.sdk.modelcontextprotocol.io/run/authorization/)).

```diff
-  - Every built-in FastMCP provider is a hosted service (Auth0, WorkOS, Clerk, Descope, ...).
+  - Every built-in FastMCP provider hands sign-in to a separate identity provider (hosted ones such as Auth0, WorkOS, Clerk and Descope, or a Keycloak server you run). None of them uses your app's own user table.
```

## 3. "Why not X?" table: hosted row
**Why:**
- **Clerk organizations:** basic orgs are free on all plans; $100/mo is the optional Enhanced B2B add-on ([Clerk pricing](https://clerk.com/pricing)).
- **SSO connection prices:**
  - Clerk: $75/mo for connections 2-15, then $60 ([Clerk pricing](https://clerk.com/pricing)).
  - WorkOS: $125/mo for 1-15, down to $65 ([WorkOS pricing](https://workos.com/pricing)).
  - Auth0: $100/mo per connection beyond the included ones ([Auth0 pricing](https://auth0.com/pricing)).
- **Auth0 agent features:** the "AI Agents" add-on adds 50% to the base price, but "Auth for MCP" is included on every plan ([Auth0 pricing](https://auth0.com/pricing)). Re-check that page in a browser before publishing; it renders differently across fetches.
- **"Python SDKs mostly verify tokens"** is too broad. WorkOS's Python SDK covers the whole API with login helpers ([workos on PyPI](https://pypi.org/project/workos/)). Sign-in itself runs on each vendor's hosted pages.

```diff
-| Auth0, Clerk, WorkOS, Stytch | Hosted; Python SDKs mostly verify tokens | Free, and your data stays in your database. Clerk charges $100/mo for orgs, Clerk and WorkOS charge $75-125 per SSO connection per month, and Auth0's agent features cost +50% |
+| Auth0, Clerk, WorkOS, Stytch | Hosted; sign-in runs on the vendor's pages, and the Python SDKs wrap the vendor API | Free, and your data stays in your database. Enterprise SSO costs $60-125 per connection per month (Auth0, Clerk, WorkOS), Clerk's advanced organization features are a $100/mo add-on, and Auth0's AI Agents add-on adds 50% to the plan price |
```

## 4. Hero clip 2: the maintenance facts are now checked
**Why:** the clip note asks for this check before posting. The verified wording is in [validation-research.md, section 3 of the addendum](../research/validation-research.md#3-hero-clip-facts-agent-split-screen).
- passlib's last release was 1.7.4 on 2020-10-08 ([PyPI](https://pypi.org/pypi/passlib/json)).
- python-jose had releases in 2025 (3.4.0 and 3.5.0) after a gap of almost four years ([PyPI](https://pypi.org/pypi/python-jose/json)).
- The FastAPI tutorial now uses PyJWT and pwdlib ([tutorial](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)).

```diff
-2. **Agent split screen.** The same "add GitHub login and API keys to this FastAPI app" prompt, with and without GotAuth's skill. Without it, the agent writes about 200 lines with passlib and python-jose; with it, about 15 lines. Check current passlib and python-jose maintenance facts before posting.
+2. **Agent split screen.** The same "add GitHub login and API keys to this FastAPI app" prompt, with and without GotAuth's skill. Without it, the agent writes about 200 lines with passlib and python-jose; with it, about 15 lines. Facts for the voice-over (checked 2026-10-03): FastAPI's own tutorial moved to PyJWT in May 2024 and to pwdlib in September 2025; passlib's last release is from October 2020. Do not call python-jose unmaintained: it shipped releases in 2025.
```

## 5. Competitor rows: qualify "no embeddable Python option"
**Why:**
- django-allauth's OIDC provider now supports DCR and CIMD ([CIMD docs](https://docs.allauth.org/en/latest/idp/openid-connect/client-id-metadata-document.html)), but it is Django-only.
- better-auth-server has an OAuth 2.1 server plugin without CIMD ([source note](https://github.com/oumarbarry/better-auth-py/blob/d2826ca2e05ecfa8c15ff22bae9430e4807a460f/src/better_auth/plugins_ext/oauth_provider/register.py#L568)).
- The pitch still holds if it says "for FastAPI and ASGI apps, on your own user table, with CIMD".

```diff
-| django-allauth | Excellent, but Django only | Not competing on Django |
+| django-allauth | Excellent, but Django only; its OIDC provider supports DCR and CIMD since 2026 | Not competing on Django |
-| [better-auth-server](https://github.com/oumarbarry/better-auth-py) | 3 stars; a parity port of Better Auth TypeScript, released 2026-09 | A Pythonic API, published tests, a security process, and no dependence on another project's release cadence |
+| [better-auth-server](https://github.com/oumarbarry/better-auth-py) | 3 stars; a parity port of Better Auth TypeScript, released 2026-09; about 3,000 tests in CI; no security policy; its OAuth server has no CIMD yet | A Pythonic API, a security process, CIMD and MCP helpers, and no dependence on another project's release cadence |
```

The public version of this table is the draft [docs/launch/comparison.md](../launch/comparison.md).
