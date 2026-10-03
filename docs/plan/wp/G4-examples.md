# G4: Examples (+ hero-clip app)

| | |
|---|---|
| Lane / wave | Growth / **Wave 2 -> 3** (part 1 on the critical path to M2) |
| Size | M |
| Depends on | Part 1: A1, S1, C4, P1, D2. Part 2: P2, P3, P5 |
| Can start | skeleton after M1; part 1 once A1, P1 and D2 merge; part 2 as P2, P3 and P5 merge |
| Write scope | `examples/fastapi-nextjs/**`, `examples/litestar-htmx/**`, `examples/README.md`, `changes/G4.*.md` |
| Allowed new deps | example-only, in each example's own `pyproject.toml` / `package.json`: fastapi, uvicorn, `gotauth[fastapi,sqlalchemy,sqlite,postgres,passkey]` (path dependency), Next.js, React, Tailwind, shadcn CLI; litestar for the second example. None in the library |

## Goal
A runnable FastAPI + Next.js app that shows the M2 scenario end to end and serves as the set for the hero clip (part 1), then gains the 2FA, passkey and org-invitation flows that Q2's browser tests drive (part 2), plus an index of all examples.

## Build
Part 1 (M2):
- `fastapi-nextjs/backend/` (`app/main.py`, config from env, `.env.example`):
  - `GotAuth` with `sqlalchemy_adapter`: SQLite file by default, Postgres when `DATABASE_URL` is set; schema via `gotauth generate` + Alembic (S1; tables `auth_*`).
  - Email + password (`require_email_verification=True`; no sender configured, so the console sender is used on localhost, section 9); GitHub (C4) from `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`, button hidden if unset; `api_key(allowed_scopes=("projects:read", "projects:write"))`. Plugin imports per 13.2 (`from gotauth.plugins.api_key import api_key`).
  - `app.include_router(auth.fastapi.router(), prefix="/api/auth")`.
  - `GET /api/projects` with `CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]` (browser) and `GET /api/v1/projects` with `ApiKeyPrincipal` + `require("projects:read")` (curl). In-memory demo data per user.
- `fastapi-nextjs/frontend/`: Next.js App Router with D2 components (sign up, sign in, GitHub button, API key manager) added via the shadcn CLI from the D2 registry, plus D2's typed client. Next.js rewrites proxy `/api/*` to the backend, so the browser sees one origin: `base_url=http://localhost:3000`, GitHub callback `http://localhost:3000/api/auth/callback/github`, no CORS.
- `compose.yaml`: backend, frontend, optional `postgres` profile; `docker compose up` serves port 3000.
- `README.md`:
  - Setup in at most 5 commands; creating the GitHub OAuth app.
  - The exact M2 scenario from `docs/plan/README.md` with commands: sign up -> verify email (console) -> GitHub login -> session cookie -> create API key -> `curl` a protected route with the key -> revoke -> 401.
  - Hero-clip script (about 45s): 0-5s the GotAuth setup (about 15 lines, one screen); 5-12s sign up, link in the console, click; 12-18s "Continue with GitHub"; 18-25s create a `projects:read` key, shown once; 25-32s `curl -H "x-api-key: gak_..." localhost:3000/api/v1/projects` -> 200; 32-38s revoke in the UI; 38-45s same `curl` -> 401. Also: font size, window layout, what to hide (`.env`, secrets).
- `AGENTS.md`: where auth is configured, how routes are protected, how to add a provider or scope, how to run tests, and to use GotAuth's APIs instead of hand-written auth.
- `backend/tests/test_m2_scenario.py`: the M2 scenario over httpx `ASGITransport`, with `fake_oauth_provider` standing in for GitHub and `fake_mailer` capturing the link.
- `litestar-htmx/` only if A2 keeps Litestar: server-rendered sign in, sign out and API keys page.
- `examples/README.md`: table of examples (`fastapi-nextjs`; `fastmcp-server` from O2; `litestar-htmx` if present) with one line and the run command each.

Part 2 (after P2, P3, P5; Q2 depends on it):
- Backend adds `two_factor()`, `passkey()` and `organization(invitation_url="http://localhost:3000/invitations/accept")`; `rp_id` resolves to `localhost`.
- Frontend adds pages with D2's TwoFactorSetup, TwoFactorChallenge (inline in SignInForm), PasskeyButton (register and usernameless sign-in) and OrgSwitcher, plus an org page to create an org and invite by email, and the invitation accept page (D2 client calls).
- Every step stays scriptable for Playwright: stable labels and `data-testid`s, no fixed waits.
- `backend/tests/test_part2_flows.py`: 2FA enable + challenge (codes from the crypto kit), passkey register + sign in with P3's `SoftAuthenticator`, org invite + accept via `fake_mailer`.

## Acceptance tests
- `test_m2_scenario.py` passes in the dev container on SQLite and on the Postgres service.
- From a clean clone, `docker compose up` plus the README scenario works by hand (integrator check at M2).
- The raw key is shown once; after revoke the `curl` returns 401 with P1's error code.
- Part 2: `test_part2_flows.py` passes on SQLite and Postgres; the M2 scenario and its test still pass unchanged.
- `next build` and `next lint` pass; the backend passes ruff and pyright.
- No secrets committed; only `.env.example`.

## Out of scope
`examples/fastmcp-server` (O2), the UI components (D2), docs site pages (G2), e2e and agent-install tests (Q2).

## Notes
- Record the versions used (FastAPI, Next.js, Node 24, Python 3.14) in the README; follow the current Next.js App Router docs for rewrites.
- Keep the backend short: the clip relies on the setup fitting on one screen, also after part 2 adds three plugin lines.
- Q2 reuses this app, so keep every step scriptable.
