# Examples

Runnable apps that use GotAuth. Work package G4 owns this index; each example is owned by the work package that builds it.

| Example | What it shows | Run | Owner |
|---|---|---|---|
| [`fastapi-nextjs/`](fastapi-nextjs/) | FastAPI backend and Next.js frontend: email and password, GitHub login, API keys; later 2FA, passkeys and organizations | `cd examples/fastapi-nextjs && docker compose up --build` (after the `.env` step in its README) | G4 |
| `litestar-htmx/` | Server-rendered Litestar app (only if work package A2 keeps Litestar) | not built yet | G4 |
| `fastmcp-server/` | FastMCP server protected by the GotAuth OAuth 2.1 server | not built yet | O2 |

## Format of an example

- Its own folder with a `README.md`: what it shows, setup in at most five commands, how to run it and its tests.
- Its own dependency files: `pyproject.toml` with `uv.lock`, and `package.json` with `pnpm-lock.yaml` for a frontend. GotAuth comes in as a path dependency on the repository root, with the extras the example needs. Examples are not part of the root uv project, so they never change the root `pyproject.toml` or `uv.lock`.
- A frontend at `examples/<name>/` or `examples/<name>/<part>/` is a Node project (CONTRIBUTING.md, "Node projects"): `"packageManager": "pnpm@12.8.1"` and a `check` script (lint, type check, tests, build). CI runs `pnpm install --frozen-lockfile` and `pnpm run --if-present check` in it.
- Configuration from environment variables, with a committed `.env.example` and no secrets.
- Runs in Docker like everything else, for example `./dev.sh --ports bash -c "cd examples/<name> && ..."` or the example's own `compose.yaml`.
