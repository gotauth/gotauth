# AGENTS.md

Instructions for coding agents working on this example app.

## Auth is GotAuth

**Use GotAuth's APIs for anything auth-related.** Do not write auth by hand:
- no password hashing
- no JWT sessions
- no `passlib`
- no `python-jose`
- no tokens in `localStorage`

GotAuth already provides sign-up, sign-in, sessions, email verification, password reset, GitHub login, API keys, two-factor authentication, passkeys and organizations with invitations.

## Where things are

**Configuration:** [backend/app/auth.py](backend/app/auth.py), the `GotAuth(...)` call:
- database
- secret
- `base_url` (the Next.js origin)
- email and password
- social providers
- plugins

**Routes:** [backend/app/main.py](backend/app/main.py).
- GotAuth's router is included at `/api/auth`.
- App routes are protected with dependencies:
  ```python
  user: Annotated[User, Depends(auth.fastapi.current_user)]                 # browser session
  key: Annotated[Principal, Depends(auth.fastapi.api_key_principal)]        # API key only
  _: Annotated[Principal, Depends(auth.fastapi.require("projects:read"))]   # scope check
  ```
  Sessions have every scope, so pair `require(...)` with `api_key_principal` when a route is for keys only.

**Frontend auth UI:** `frontend/src/components/gotauth/`, from GotAuth's shadcn registry. Pages use them inside `<GotAuthProvider baseURL="/api/auth">` ([frontend/src/app/providers.tsx](frontend/src/app/providers.tsx)). Call GotAuth through `useGotAuthClient()` or `useSession()`, never with hand-written fetches to `/api/auth`.

**Same origin:** the browser talks only to Next.js. `/api/*` is proxied to FastAPI ([frontend/next.config.ts](frontend/next.config.ts)). Keep it that way, because cookies and the OAuth callback rely on it.

## How to...

**Add a social provider:**
1. In `auth.py`, add it to `social_providers` (`from gotauth.social import google`), reading its id and secret from the environment.
2. Add the variables to `.env.example`.
3. The sign-in page shows the button by itself (`GET /api/config`).
4. The callback URL is `http://localhost:3000/api/auth/callback/<id>`.

**Add an API key scope:**
1. Add it to `SCOPES` in `auth.py`. The keys page reads the list from `GET /api/config`.
2. Protect routes with `require("<scope>")`.

**Add a GotAuth plugin:**
1. Add it to `plugins` in `auth.py`.
2. Write a migration: `uv run gotauth generate --auth app.auth:auth -m "<plugin> tables"`.
3. Check the revision: a NOT NULL column added to an existing table needs a `server_default`, or upgrading a database with rows fails (issue #53).
4. Apply it: `uv run alembic upgrade head`.

**Organization-scoped data:** the session's active organization is `session.active_organization_id` (set with the switcher), and `auth.fastapi.require(permission={"project": ["read"]})` checks the caller's role in it.

## Run the checks

From the repository root (Docker only; nothing is installed on the host):

```bash
./dev.sh bash -c "cd examples/fastapi-nextjs/backend && export UV_PROJECT_ENVIRONMENT=.venv && uv sync --locked && uv run ruff check . && uv run pyright && uv run pytest"
./dev.sh bash -c "cd examples/fastapi-nextjs/frontend && pnpm install --frozen-lockfile && pnpm run check"
```

`backend/tests/test_m2_scenario.py` and `backend/tests/test_part2_flows.py` must keep passing. They are the walkthroughs in README.md, and the browser tests (Q2) drive the same pages. Keep their labels and `data-testid`s stable.
