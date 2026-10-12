# FastAPI + Next.js with GotAuth

A FastAPI backend and a Next.js frontend with:
- sign-up with email and password, and email verification
- "Continue with GitHub"
- a session cookie
- API keys with scopes for scripts

All of the auth setup is in [backend/app/auth.py](backend/app/auth.py).

**How the pieces fit:**
- The browser only talks to `http://localhost:3000`. Next.js forwards everything under `/api` to FastAPI ([frontend/next.config.ts](frontend/next.config.ts)), so cookies, the GitHub callback and the API share one origin, with no CORS setup.
- GotAuth's routes are at `/api/auth`.
- The app's own routes are `/api/projects` (session) and `/api/v1/projects` (API key with `projects:read`).

Built with FastAPI 0.142, Python 3.14, Next.js 16.4, React 19.3, Tailwind CSS 4.3, shadcn CLI 4.21 and Node 24 (checked 2026-10-12).

## Run it

Needs Docker. From the repository root:

```bash
cd examples/fastapi-nextjs
cp .env.example .env
docker compose run --rm backend gotauth secret   # paste the output into .env as GOTAUTH_SECRET
docker compose up --build
```

Then open http://localhost:3000.

**GitHub login (optional).**
1. Create an OAuth app at https://github.com/settings/developers.
2. Set the homepage to `http://localhost:3000` and the callback URL to `http://localhost:3000/api/auth/callback/github`.
3. Put its client id and secret in `.env`.
4. Restart. Without them, the GitHub button is hidden.

**Database.** SQLite in a Docker volume by default. For Postgres:
1. Uncomment `DATABASE_URL` in `.env`.
2. Run `docker compose --profile postgres up --build`.

On start, the backend runs `alembic upgrade head`. GotAuth's tables (`auth_user`, `auth_session` and so on) come from a revision made with `gotauth generate`. After adding a GotAuth plugin, run `gotauth generate --auth app.auth:auth -m "..."` to add a revision for its tables.

## The walkthrough (milestone M2)

1. **Sign up.** Go to http://localhost:3000/sign-up, enter an email and a password, and submit. The answer is "Check your email" whether or not the address was already taken.
2. **Verify the email.** On localhost GotAuth prints emails instead of sending them. Find the link in the `docker compose up` output, or run `docker compose logs backend`, and open it. You land on the sign-in page; verifying does not sign you in.
3. **Log in with GitHub.** Choose "Continue with GitHub". If your GitHub account's verified email matches the one you signed up with, it is linked to the same account. Signing in with the email and password works too.
4. **Check the session cookie.** `gotauth.session_token` is set (DevTools, Application, Cookies). It is HttpOnly, so page scripts cannot read it.
5. **Create an API key.** Go to "API keys" and choose "Create key", with the name `laptop` and the scope `projects:read`. The key is shown once: copy it now.
6. **Call the API with the key:**
   ```bash
   curl -H "x-api-key: gak_..." http://localhost:3000/api/v1/projects
   ```
   This returns 200 and the projects.
7. **Revoke the key** in the "API keys" page, then run the same `curl` again. This time it returns:
   ```
   401 {"error": {"code": "API_KEY_INVALID", ...}}
   ```

[backend/tests/test_m2_scenario.py](backend/tests/test_m2_scenario.py) runs the same steps on SQLite and Postgres. A stub stands in for GitHub, and a capturing mailer stands in for the console.

## Hero clip script (about 45 seconds)

**Setup.**
- **Screen:** 1920x1080. The editor and the browser side by side, with a terminal under the browser.
- **Font sizes:** 18 pt in the editor and terminal. Browser zoom at 125%.
- **Hide:** `.env`, the terminal history, the bookmarks bar and the browser profile picture.
- **Prepare:** sign up once beforehand with a throwaway address, then delete the volume (`docker compose down -v`) so the take starts clean.

| Time | On screen |
|---|---|
| 0-5s | `backend/app/auth.py`: the `GotAuth(...)` call, one screen |
| 5-12s | Sign up; switch to the terminal, click the link GotAuth printed; the sign-in page appears |
| 12-18s | "Continue with GitHub", approve, the projects page appears |
| 18-25s | "API keys", create `laptop` with `projects:read`; the key is shown once; copy it |
| 25-32s | `curl -H "x-api-key: gak_..." localhost:3000/api/v1/projects` returns 200 and the JSON |
| 32-38s | Revoke the key in the UI |
| 38-45s | The same `curl` returns 401 `API_KEY_INVALID` |

## Develop and test

From the repository root, in the dev container:

```bash
# Backend: lint, types, and the M2 test on SQLite and Postgres
./dev.sh bash -c "cd examples/fastapi-nextjs/backend && export UV_PROJECT_ENVIRONMENT=.venv && uv sync --locked && uv run ruff check . && uv run pyright && uv run pytest"

# Frontend: lint, types and build
./dev.sh bash -c "cd examples/fastapi-nextjs/frontend && pnpm install --frozen-lockfile && pnpm run check"
```

`UV_PROJECT_ENVIRONMENT=.venv` keeps the example's environment apart from the library's.

**Running without Docker Compose** (two terminals):
- **Backend**, on port 8000:
  ```bash
  set -a && . ../.env && set +a   # nothing else loads .env
  uv run alembic upgrade head && uv run uvicorn app.main:app --reload
  ```
- **Frontend:** `pnpm dev`, on port 3000. `BACKEND_URL` defaults to `http://localhost:8000`.

## Where the UI comes from

`frontend/src/components/gotauth/`, `src/hooks/use-session.ts` and `src/lib/gotauth-client.ts` come from GotAuth's shadcn registry, added with:

```bash
pnpm dlx shadcn@4.21.3 add @gotauth/sign-in-form @gotauth/sign-up-form @gotauth/social-buttons @gotauth/user-button @gotauth/api-key-manager @gotauth/use-session
```

They are your code now, so edit them freely. Until the registry is published at `gotauth.ablacky.com`, build it from this repository instead:
1. Run `pnpm --dir registry build`.
2. Serve `registry/public`, for example with `python3 -m http.server 8765` in that folder.
3. Point `@gotauth` in `components.json` at `http://127.0.0.1:8765/r/{name}.json`.
