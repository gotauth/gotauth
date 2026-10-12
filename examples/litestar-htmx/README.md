# Litestar + htmx with GotAuth

Server-rendered pages with Litestar and Jinja, made interactive with htmx:
- sign up with email verification
- sign in and sign out
- an API keys page

All of the auth setup is in [app/auth.py](app/auth.py).

**How it works.**
- Every change goes from htmx straight to GotAuth's JSON endpoints under `/api/auth`. That covers sign-in, sign-out, and creating and deleting keys.
- GotAuth checks the `Origin` header and the JSON content type on those endpoints, so a cross-site form cannot use the session cookie.
- The app's own routes ([app/main.py](app/main.py)) only render pages. They read the session through `GotAuthPlugin`'s `principal` dependency, which also renews an active session's cookie. They call `auth.api` with the browser's cookie for the user and the key list.
- [app/static/app.js](app/static/app.js) is a small htmx extension that sends forms as JSON. It also turns GotAuth's answers into redirects, messages, and the new key, which is shown once.

Built with Litestar 2.24, Jinja 3.1, htmx 2.0.11 and Python 3.14 (checked 2026-10-12).

## Run it

From the repository root, in the dev container. `UV_PROJECT_ENVIRONMENT=.venv` keeps the example's environment apart from the library's.

```bash
./dev.sh --ports bash
cd examples/litestar-htmx && export UV_PROJECT_ENVIRONMENT=.venv && uv sync --locked
[ -f .env ] || echo "GOTAUTH_SECRET=$(uv run gotauth secret)" > .env   # once
set -a && . ./.env && set +a                    # nothing else loads .env
uv run gotauth migrate --auth app.auth:auth && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then open http://localhost:8000. `gotauth migrate` creates GotAuth's tables in `app.db`. `.env.example` lists the other settings.

**The walkthrough:**
1. Create an account.
2. Open the verification link that GotAuth prints in the terminal. On localhost, emails are printed instead of sent.
3. Sign in.
4. Open "API keys" and create a key. Copy it: it is shown only once.
5. Delete the key.
6. Sign out.

## Tests

```bash
./dev.sh bash -c "cd examples/litestar-htmx && export UV_PROJECT_ENVIRONMENT=.venv && uv sync --locked && uv run ruff check . && uv run pyright && uv run pytest"
```

The tests drive the same requests htmx sends:
- sign-up, verification, sign-in, the key list (with HTML escaping) and sign-out
- refusal of plain form posts and of requests from another origin
