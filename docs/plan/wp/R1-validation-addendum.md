# R1: Validation addendum (MCP auth evidence) and comparison draft

| | |
|---|---|
| Lane / wave | Research / **Phase 0**, any time before M0 |
| Size | S (1 agent-day) |
| Depends on | none |
| Can start | now |
| Write scope | `docs/research/**` (append to `validation-research.md`; raw snapshots in `docs/research/raw/`), `docs/launch/comparison.md`, `docs/requests/R1-*.md` |
| Allowed new deps | none (curl, the GitHub REST API, `gh` if already authenticated, a browser; no code in `src/`) |

## Goal
Public online evidence on Python MCP auth demand, a checked reading of the current MCP authorization spec, verified facts for the hero clip, and a fair, sourced comparison page. M0 waits for this. Public sources only: no interviews, surveys or DMs.

## Build
1. **MCP auth pain, new gate G9.**
   - GitHub issues and discussions about auth in the FastMCP repo (confirm its current owner from the PyPI project URLs) and `modelcontextprotocol/python-sdk`, last 12 months, sorted by reactions. Issues via `GET https://api.github.com/search/issues?q=repo:<repo>+is:issue+auth&sort=reactions` (repeat with `oauth`); discussions via `gh api graphql` if gh is logged in, else the web list sorted by top. Record title, link, date, state, reactions, comments.
   - Hacker News via Algolia (`https://hn.algolia.com/api/v1/search?query=<q>&tags=story`) for "MCP auth", "MCP OAuth", "FastMCP auth": points, comments, date.
   - r/mcp if reachable (Reddit directly, else the PullPush archive as in the existing research; say which).
   - Add **G9 "MCP auth demand"** to the gate table. Threshold: >= 50 combined reactions on Python MCP auth requests (FastMCP, python-sdk) in 12 months, or one HN story on MCP auth with >= 50 points. Marginal: 25-49 reactions. Record the result and the evidence rows.
2. **MCP authorization spec.** Read revision 2026-07-28 on modelcontextprotocol.io; confirm it exists and is the latest (if not, use the latest and say so). Record with section links and short quotes: requirement levels for client ID metadata documents (CIMD), dynamic client registration and pre-registration; RFC 9728 protected resource metadata; RFC 8707 resource indicators; PKCE; scopes and step-up; token audience; loopback redirects. Compare with CONTRACTS 12.2 (token claims, revocation semantics), 12.3 (endpoints, OAuth server rules), 12.4 (MCP surface) and O1's brief; on any difference, write `docs/requests/R1-o1-mcp-spec.md` with the exact change (before M0 a request is enough; after M0 the integrator turns it into a CCR).
3. **Hero-clip facts.** From `https://pypi.org/pypi/<name>/json`: latest version and upload date of passlib and python-jose. From the FastAPI security tutorial: which hashing and JWT libraries it recommends now (short quote, link, date checked).
4. **Competitor detail** for better-auth-server (oumarbarry/better-auth-py) and reauth (frankie567/reauth): README claims, test count and whether CI runs them, latest releases and changelog notes, license, security policy, stars, pypistats downloads. Mark unverified claims.
5. **Outputs.**
   - `docs/research/validation-research.md`: new section "MCP auth addendum (<date>)" with tables for items 1-4, the G9 row in the gate table, and the exact queries. Existing sections stay as they are; corrections go in the addendum.
   - `docs/launch/comparison.md`: public page draft covering fastapi-users, reauth, better-auth-server, AuthX, Authlib, FastMCP's built-in providers, hosted services (Auth0, Clerk, WorkOS) and django-allauth. Feature matrix (yes / no / partial / planned, every cell sourced), "when to choose X instead" per row, a "last checked" date; GotAuth features marked "planned" until they ship.

## Acceptance tests
- Every number and claim has a link and a retrieval date; every query can be re-run; raw API responses saved as JSON in `docs/research/raw/`.
- G9 has a threshold, a result and evidence rows.
- The spec summary cites section anchors; quotes are under 15 words, the rest is paraphrase.
- The comparison page states each competitor's strengths and holds nothing that a public source cannot confirm.
- No em dashes or emojis (grep).

## Out of scope
- Editing build-plan.md or CONTRACTS.md (request files only); launch posts (G5); the landing page (G1).

## Notes
- The existing research marks the CIMD claim as coming from secondary sources. The spec text decides.
- The unauthenticated GitHub search API allows about 10 requests per minute; space the calls.
