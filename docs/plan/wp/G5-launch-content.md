# G5: Launch content drafts

| | |
|---|---|
| Lane / wave | Growth / **Wave 3** |
| Size | M |
| Depends on | `docs/research`, R1 (comparison), G3 (`gotauth check`), G4 and O2 examples, Q2 (`agent-baseline.md`) |
| Can start | outlines after M2; final numbers and code after O2 and Q2 |
| Write scope | `docs/launch/**` except `comparison.md` (R1) and `agent-baseline.md` (Q2) |
| Allowed new deps | none |

## Goal
Ready-to-post drafts for launch week (build plan checklist): honest, specific, and checked against `docs/research` and the shipped code. The owner posts; this WP only writes.

## Build
Files in `docs/launch/`:
- `show-hn.md`: title "Show HN: GotAuth - login for your Python MCP server from your own user table"; body; first comment (what it is, what is not done yet, how to try it in two minutes).
- `reddit-fastapi.md`; `reddit-python-showcase.md` with r/Python's required sections "What My Project Does", "Target Audience", "Comparison"; `reddit-mcp.md`.
- `pycoders-submission.md`, `python-bytes-suggestion.md`, `talk-python-pitch.md` (episode angle, short bio placeholder, three talking points).
- `devto-tutorial-fastmcp.md`: "Login for your FastMCP server from your own user table in 10 lines". Code follows CONTRACTS 12.4 and 13.2 (`fastmcp_auth(auth, resource=..., scopes=[...])`, `from gotauth.plugins.oauth_provider import oauth_provider`, `app.mount("/", auth.well_known())`) and `examples/fastmcp-server`.
- `social-threads.md`: a launch thread plus four technical threads: CIMD for MCP clients; hashed session tokens; why `act` claims matter for agents; no account enumeration. Each post within the platform's length limit.
- `hero-clip-scripts.md`: the three build-plan clips (MCP login and revoke; agent split screen with and without the skill; `uvx gotauth check` score then fixes): shot list, timing, on-screen text, exact commands. Start from the scripts in the G4 and O2 example READMEs and keep them consistent.
- `pycon-2027-proposal.md`: "Auth for MCP servers in Python": title, abstract, audience, outline with timings, why now.
- `fastmcp-docs-pr.md`: PR title and description, plus the docs snippet for FastMCP's auth-provider docs.
- `faq.md`: security questions (where data lives and the `auth_` table prefix next to an existing `user` table, what is hashed or encrypted at rest, enumeration, CSRF and origin checks, rate limits, how fast revocation applies (CONTRACTS 12.2: at once in-process, at token expiry for remote JWT-only checks unless introspection is on), OAuth server scope, threat model and conformance status, vulnerability reporting (`SECURITY.md`, Q1), maintenance plans).
- `fact-check.md`: every number and claim in the drafts with its source (a `docs/research` line, URL or test) and the date checked.

## Acceptance tests
- Every claim appears in `fact-check.md` with a source; no unmeasured metrics (stars, downloads, users, speed).
- Agent comparison numbers come from `agent-baseline.md`, not the build plan's estimates ("about 200 lines", "about 15").
- Tutorial and FastMCP snippet code is copied from a tested file or extracted and run against the example.
- A grep in the PR shows no em or en dashes, no emojis and none of the banned words in AGENT-RULES section 5.
- The r/Python draft has the three required sections; the Show HN title matches the build plan.

## Out of scope
Posting (owner), the comparison page (R1), docs pages (G2), recording clips (owner), the landing page (G1).

## Notes
- Check each venue's current rules before finalizing: r/Python showcase rules, Show HN guidelines, the PyCoder's form, FastMCP's contributing guide and docs layout.
- PyCon US 2027 CFP dates were not announced on 2026-10-03; check pythondeadlin.es and us.pycon.org.
- Re-check passlib and python-jose maintenance status and competitor numbers on the day of posting; describe competitors fairly.
- Lead with the MCP and agent angle; the fastapi-users migration is the second message (build plan positioning).
