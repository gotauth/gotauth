# G2: Docs, llms.txt, agent skill, Context7

| | |
|---|---|
| Lane / wave | Growth / **Wave 3** |
| Size | L |
| Depends on | S1, A1, A2 (adapters and integrations); each module README; R1 (`docs/launch/comparison.md`) |
| Can start | after M2; plugin pages fill in as P*, O* and I1 merge |
| Write scope | `apps/docs/**`, `skills/**`, `.github/workflows/docs.yml` (new file) |
| Allowed new deps | docs dependency group only, added up front by F1 (Zensical or mkdocs-material, mkdocstrings[python], a link checker, a tokenizer for the count script); anything else by request. Nothing at runtime |

## Goal
A docs site at `gotauth.dev/docs` that takes a developer or a coding agent from install to a protected route, plus agent entry points (llms.txt, a skill, Context7) so agents pick GotAuth instead of hand-rolling auth.

## Build
- Generator: Zensical if it is stable at build time, else Material for MkDocs. Status read from zensical.org on 2026-10-03: 0.0.x alpha releases, 0.1.0 announced for 2026-11-05 as the start of a dependable release line, mkdocstrings supported; Material for MkDocs gets critical fixes until 2027-05-05. Re-check, decide, record choice and versions in `apps/docs/README.md`.
- API reference via mkdocstrings (Google-style docstrings) for every public module.
- Pages:
  - Quickstart (FastAPI): install -> `GotAuth(...)` -> router -> `gotauth generate` + migration -> sign up -> protected route. Under 15k tokens.
  - Concepts: principals (12.1, incl. the `resource:action` scope form), sessions (7), plugins and hooks (5), schema and migrations (2, the `auth_` table prefix, S1 CLI), events (14).
  - One page per plugin and integration, built from the module READMEs.
  - MCP guide: FastMCP and the MCP SDK (12.4), walking through `examples/fastmcp-server`; same-process vs remote verification and `introspect=True`.
  - API keys guide, agents guide, migrating from fastapi-users (I1), security model (links Q1's threat model), comparison (from R1's `docs/launch/comparison.md`), troubleshooting (error codes, cookies behind proxies, `trusted_origins`, email in tests and `auth.drain()`).
  - Trade-offs the contracts require the docs to state: cookie cache delays revocation by up to `max_age` (7); `require_email_verification=False` reveals existing accounts (9.1); remote JWT-only resource servers accept a revoked token until it expires (12.2).
- Agent readiness:
  - `llms.txt` and `llms-full.txt` generated at build time (llmstxt.org format); every page also served as `.md`.
  - "Copy page as Markdown" button on every page.
  - `skills/gotauth/SKILL.md` (Agent Skills format, `name` + `description` front matter): when to use GotAuth; the 10-line FastAPI setup; decision rules ("never hand-roll JWT/passlib auth", "use `CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]` and `auth.fastapi.require(...)`", "API keys come from the `api_key` plugin"); adding MCP auth with `fastmcp_auth`; links to llms.txt. Ready to publish on skills.sh.
  - `apps/docs/CONTEXT7.md`: steps and config to list GotAuth on Context7.
  - `robots.txt` allowing AI crawlers, with the sitemap.
- Deploy: free static hosting under `gotauth.dev/docs` (same site as G1's landing or a path route); `.github/workflows/docs.yml` builds on PRs and deploys from `main`, actions pinned by commit SHA.
- Docs MCP server: cut-list item 1, not built for v0.1.

## Acceptance tests
- Strict build (warnings fail) passes in Docker.
- Link check passes (internal always; external with retries).
- Every code sample is extracted and run in CI by `apps/docs/tests/test_samples.py` against `gotauth.testing` (`make_auth`, `make_client`); a skipped block needs a written reason.
- `apps/docs/scripts/count_tokens.py`: quickstart Markdown < 15,000 tokens (tokenizer recorded); fails CI above it.
- `llms.txt` lists every page; each `.md` URL exists in the build output.
- `SKILL.md` front matter validates and its FastAPI snippet runs in the samples test.
- `robots.txt` and `sitemap.xml` exist in the build output.

## Out of scope
Landing page (G1), launch posts (G5), running the agent-install test (Q2), module READMEs (each WP), docs MCP server (cut).

## Notes
- Samples follow CONTRACTS.md and the build-plan snippets: imports per 13.2 (`from gotauth.plugins.api_key import api_key`), `CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]`, `fastmcp_auth(auth, resource=..., scopes=[...])`, `app.mount("/", auth.well_known())`.
- Check the current skills.sh, Context7 and llms.txt conventions at build time; record what was used.
- AGENT-RULES section 5 writing rules apply to every page.
