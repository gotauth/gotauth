# Fact check

Every number and claim in the launch drafts, with its source and the date it was
checked. **Re-check** marks facts that change: check them again on the day of posting
and update the drafts if they moved.

Rules for the drafts (work package G5):
- No unmeasured metrics: no stars, downloads, users or speed claims for GotAuth.
- Agent comparison numbers come only from `agent-baseline.md` (not written yet; see
  "Pending" below).
- Code in the tutorial and the FastMCP snippet is copied from tested files (see "Code").

## Outside facts

| Claim | Used in | Source | Checked |
|---|---|---|---|
| The MCP Python SDK's docs say of the authorization server: "You don't write this. It's your identity provider." | show-hn | [py.sdk.modelcontextprotocol.io/run/authorization](https://py.sdk.modelcontextprotocol.io/run/authorization/); `docs/research/validation-research.md` (corrections, item 2) | 2026-10-03. **Re-check** |
| FastMCP's built-in providers hand sign-in to a separate identity provider; none keeps users in the app's database | show-hn, reddit-python-showcase, devto | [gofastmcp.com/servers/auth/authentication](https://gofastmcp.com/servers/auth/authentication); research (corrections, item 3) | 2026-10-03 |
| Client ID metadata documents are a SHOULD for authorization servers since MCP revision 2025-11-25; revision 2026-07-28 deprecates dynamic registration in their favor | reddit-mcp, social-threads (CIMD), devto, pycon, talk-python | [2025-11-25 authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog); research (corrections, item 1) | 2026-10-03. **Re-check** the current spec revision |
| Amplifying.ai benchmark, February 2026 (2,430 prompts, 3 models): Python auth was "100% Custom/DIY: JWT + passlib + python-jose" | show-hn, python-bytes, talk-python, pycon | [amplifying.ai report](https://amplifying.ai/research/claude-code-picks/report); research (evidence, lines on G4) | 2026-10-03 |
| FastAPI's docs replaced python-jose with PyJWT on 2024-05-20 and passlib with pwdlib on 2025-09-29 | show-hn, python-bytes, talk-python | [fastapi#11589](https://github.com/fastapi/fastapi/pull/11589), [fastapi#13917](https://github.com/fastapi/fastapi/pull/13917); research ("What the clip may say") | 2026-10-03 |
| passlib's last release is 1.7.4, 2020-10-08 | hero-clip-scripts (gotauth check output) | [PyPI JSON](https://pypi.org/pypi/passlib/json) | 2026-10-16. **Re-check** |
| python-jose: releases before 3.4.0 are affected by CVE-2024-33663 and CVE-2024-33664; latest 3.5.0 (2025-05-28). Do not call it unmaintained | hero-clip-scripts | [PyPI JSON](https://pypi.org/pypi/python-jose/json), [GHSA-6c5p-j8vq-pqhj](https://github.com/advisories/GHSA-6c5p-j8vq-pqhj), [GHSA-cjwg-qfpm-7377](https://github.com/advisories/GHSA-cjwg-qfpm-7377) | 2026-10-16. **Re-check** |
| fastapi-users has been in maintenance mode since 2025-10-25 and still gets security fixes; latest 15.0.5 (2026-03-27) | reddit-fastapi, reddit-python-showcase | [discussion #1543](https://github.com/fastapi-users/fastapi-users/discussions/1543), [PyPI JSON](https://pypi.org/pypi/fastapi-users/json) | 2026-10-16. **Re-check** |
| Embeddable Python options for a FastAPI app: django-allauth's OIDC provider has CIMD but is Django-only; better-auth-server's OAuth server has RFC 8707 and DCR but no CIMD | show-hn | research (corrections, item 4): [allauth CIMD docs](https://docs.allauth.org/en/latest/idp/openid-connect/client-id-metadata-document.html), [better-auth-py register.py](https://github.com/oumarbarry/better-auth-py/blob/d2826ca2e05ecfa8c15ff22bae9430e4807a460f/src/better_auth/plugins_ext/oauth_provider/register.py#L568) | 2026-10-03. **Re-check** |
| The usual answers for MCP sign-in are a hosted identity provider (Auth0, WorkOS, Clerk) or Keycloak | reddit-mcp | `comparison.md`; [FastMCP integrations](https://gofastmcp.com/llms.txt); research (corrections, item 3) | 2026-10-16 |
| Competitor descriptions (Authlib, FastMCP providers, Auth0, Clerk, WorkOS, django-allauth) | reddit-python-showcase | `comparison.md` ("When to choose something else") | 2026-10-04. **Re-check** |
| Show HN: must be something people can try, no sign-up wall, no landing pages, no asking for upvotes | show-hn, README | [news.ycombinator.com/showhn.html](https://news.ycombinator.com/showhn.html) | 2026-10-16 |
| FastMCP contributing: external PRs need a linked issue with an auto-close keyword and an assigned author (unless the issue has the `prs welcome` label); third-party integrations generally belong in a separate package; new pages go in `docs/docs.json`; AI assistance is welcome under the same standards, without generated boilerplate | fastmcp-docs-pr | [gofastmcp.com/development/contributing](https://gofastmcp.com/development/contributing) | 2026-10-16. **Re-check** |
| FastMCP's provider pages are under gofastmcp.com/integrations/ (PropelAuth, Auth0, WorkOS and others) | fastmcp-docs-pr | [gofastmcp.com/llms.txt](https://gofastmcp.com/llms.txt), [PropelAuth page](https://gofastmcp.com/integrations/propelauth) | 2026-10-16 |
| PyCoder's takes projects, articles and events through an external form, with no promise of inclusion | pycoders-submission | [pycoders.com/submissions](https://pycoders.com/submissions) | 2026-10-16 |
| Python Bytes asks for topic ideas by email; cached copies give contact@pythonbytes.fm | python-bytes-suggestion | [pythonbytes.fm](https://pythonbytes.fm) ("Suggest a headline") | 2026-10-16, from search results only. **Confirm on the live site** |
| Talk Python asks for show ideas at contact@talkpython.fm | talk-python-pitch | [talkpython.fm/about](https://talkpython.fm/about) | 2026-10-16, from search results only. **Confirm on the live site** |
| PyCon US 2026 call for proposals closed 2025-12-19 (2025: 2024-12-19); 2026 and 2027 are in Long Beach; 2027 dates not announced | pycon-2027-proposal | [Simon Willison, 2025-11-02](https://simonwillison.net/2025/Nov/2/pycon-us-2026/) | 2026-10-16. **Re-check** at us.pycon.org |
| Only GotAuth 0.0.1 is on PyPI | README | [PyPI JSON](https://pypi.org/pypi/gotauth/json) | 2026-10-20. **Re-check**: v0.1.0 must be out before posting |
| Reddit rules for r/Python, r/FastAPI and r/mcp | reddit-* | Not checked: reddit.com returned a block page to automated reads | **Check by hand before posting** |

## GotAuth facts

| Claim | Used in | Source |
|---|---|---|
| MIT license; Python >= 3.11; FastAPI, Starlette and Litestar | all | `LICENSE`, `pyproject.toml`, `src/gotauth/integrations/` |
| Tables prefixed `auth_` (`auth_user`), configurable with `advanced.table_prefix` | show-hn, reddit-fastapi, devto, faq | CONTRACTS section 2 (table names), `docs/plan/CONTRACTS.md` |
| Social providers: GitHub, Google, Microsoft, Apple, Discord, GitLab, generic OIDC | reddit-fastapi | `src/gotauth/social/__init__.py` |
| Plugins: two-factor (TOTP, backup codes, email codes), passkeys, magic links and email codes, organizations, admin, API keys, agents, OAuth provider | all | `src/gotauth/plugins/*/README.md` |
| `auth.fastapi.current_user`, `require(...)`, `router()`, `add_exception_handlers`, `well_known()` | reddit-fastapi, reddit-python-showcase | `src/gotauth/integrations/fastapi/README.md` |
| OAuth server: code + PKCE (S256, required), refresh rotation with reuse detection, client credentials, OIDC, RFC 8414, JWKS with rotation, RFC 7662, RFC 7009, RFC 8707, CIMD, optional RFC 7591, RFC 9728; targets MCP authorization 2026-07-28 | show-hn, reddit-mcp, faq | `src/gotauth/plugins/oauth_provider/README.md`, `_server.py` (grant types) |
| CIMD fetches: public addresses only after DNS resolution, no redirects, 5 s timeout, 5 KB limit; loopback-redirect CIMD clients always see the consent screen | reddit-mcp, social-threads, faq | `src/gotauth/plugins/oauth_provider/README.md` (Rules) |
| `fastmcp_auth(auth, resource=..., scopes=[...])`, `current_access()`, 403 `insufficient_scope` for a missing tool scope, `mcp_sdk_auth(...)` | show-hn, reddit-mcp, devto, social-threads | `src/gotauth/integrations/mcp/README.md`, `examples/fastmcp-server` |
| Revocation: in-process at once (cache up to 5 s allowed); remote JWT-only at token expiry (`access_token_ttl`, 10 minutes by default); with introspection within 5 s; with the session cookie cache on, a revoked session works until the cache expires (`max_age`, 5 minutes by default) | reddit-mcp, devto, faq, social-threads | CONTRACTS 7 and 12.2; `src/gotauth/integrations/mcp/README.md` ("Same process or remote") |
| A banned user is refused on every credential, including `verify_access_token`, introspection and the refresh grant | faq | `tests/security/test_bans.py`, CCR 015 |
| Agents: owned by a user or an organization, own API keys and OAuth clients; linked clients' tokens carry `act: {"sub": "<agent id>"}`; revoking an agent revokes its keys and its clients' tokens in one transaction | show-hn, reddit-mcp, social-threads, reddit-python-showcase, talk-python | `src/gotauth/plugins/agent/README.md` |
| Lookups compare secrets in constant time | social-threads | AGENT-RULES section 5 (`hmac.compare_digest`); CONTRACTS 8 (crypto kit `equal`) |
| CIMD is on by default (`allow_cimd=True`) and cannot be turned off with `mcp=True`; dynamic registration needs `allow_dynamic_registration=True` | social-threads | `src/gotauth/plugins/oauth_provider/_rules.py`, README |
| Every bearer secret is stored only as a SHA-256 hash; passwords scrypt N=2^15, r=8, p=3 (or argon2id); TOTP secrets, signing keys and stored provider tokens AES-256-GCM | social-threads, faq | CONTRACTS 8; `docs/security/threat-model.md`; `src/gotauth/plugins/two_factor/README.md` |
| The raw-secret scan covers sign-up, sessions, API keys, OAuth, two-factor, magic links and invitations | social-threads, faq | `tests/security/test_raw_tokens.py` |
| Enumeration: reset, verification, magic links and email codes answer the same; sign-in for an unknown email checks a dummy hash; sign-up hides existing accounts only with email verification on | social-threads, faq | CONTRACTS 9.1; `tests/security/test_enumeration.py` |
| Origin and content-type rules; cookie flags HttpOnly, Secure (except localhost), SameSite=Lax | faq | CONTRACTS 7 and 10.1; `tests/security/test_requests.py` |
| Rate-limit defaults | faq | CONTRACTS 10.2 |
| Threat model, ASVS 5.0 Level 2 mapping for chapters V6 to V11, review checklist; OpenID conformance run not done | show-hn, reddit-mcp, reddit-python-showcase, faq | `docs/security/`; status row Q1 in `docs/plan/README.md` |
| Vulnerability reporting and response targets | faq | `SECURITY.md` |
| fastapi-users importer keeps user ids and password hashes (rehashed at the next sign-in) | reddit-fastapi, reddit-python-showcase, faq | `src/gotauth/importers/fastapi_users/README.md` |
| `gotauth check`: 13 rules, `ast` only, standard library only, no network, SARIF output | show-hn, reddit-fastapi, social-threads, python-bytes | `src/gotauth/checkup/README.md` |
| `gotauth check` on the seeded hand-rolled app: 4 findings (3 high, 1 medium), score 49/100; on the seeded GotAuth app: no findings, 100/100 | hero-clip-scripts | Run on 2026-10-16 in this repository (`./dev.sh uv run gotauth check scripts/agent-install-test/checker/fixtures/bad_app`, then `good_app`). **Re-run** before recording |
| Not done yet: OpenID conformance run, token exchange (RFC 8693), SAML and SCIM, a Flask adapter ("when users ask for them"); Django is out of scope; one maintainer; pre-1.0 | all | `docs/build-plan.md` (roadmap "Later" row, out of scope list), `docs/plan/README.md` (status), `SECURITY.md` |
| Example versions: FastMCP 4.1.3, FastAPI 0.143, Python 3.14 | devto | `examples/fastmcp-server/README.md` |

## Code

- **Tutorial and FastMCP snippet:** every line of every Python block in
  `devto-tutorial-fastmcp.md` and `fastmcp-docs-pr.md` appears in
  `examples/fastmcp-server/app/auth.py` or `app/main.py` (lines shown as `...` are left
  out, not changed). The tutorial shows `app/auth.py` in full and the auth-related
  parts of `app/main.py`, and has the reader clone the example, so every step runs.
  Checked with a script that looks up each stripped line in those files: 0 lines
  missing. The example's tests
  (`examples/fastmcp-server/tests`) and `tests/e2e/test_mcp_flow.py` run that code.
- **r/FastAPI and r/Python snippets:** from `src/gotauth/integrations/fastapi/README.md`.
- **Show HN "try it":** the seven commands were run on 2026-10-16 in the dev container
  on a fresh copy of the repository: from `uv sync` to the server answering `POST /mcp`
  with a 401 and the RFC 9728 `resource_metadata` link took 15 seconds with a warm uv
  cache. It printed the MCP URL and the MCP Inspector client id. The MCP Inspector part
  was not run here (it needs a desktop browser); `tests/e2e/test_mcp_flow.py` covers
  the same flow in a real browser.
- **Social posts:** 22 posts, each at most 280 characters with links counted in full;
  checked with a script on 2026-10-16.

## Changed from the brief

- **Tutorial title:** the brief suggested "... in 10 lines". The example's auth setup
  is longer than that (the `GotAuth(...)` call alone is about 20 lines), so the title
  leaves the number out.
- **"Launch posts on r/FastAPI get 10 to 45 upvotes":** in the early planning notes, but
  no source in `docs/research`, so no draft uses it.

## Pending

- **Agent comparison numbers** (hero clip 2, and any "lines of code" claim): fill in
  from `agent-baseline.md` and the harness's `summary.md` once the maintainer runs
  `scripts/agent-install-test/run.sh` and `run.sh --baseline` with their own key.
- **Before posting:** v0.1.0 on PyPI, the docs site live, and `comparison.md` updated
  from "planned" to what shipped (work package R1). See [README.md](README.md).
