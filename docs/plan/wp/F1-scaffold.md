# F1: Repo scaffold, Docker dev env, tooling, CI

| | |
|---|---|
| Lane / wave | Foundation / **Phase 0**, first work package |
| Size | S (1 agent-day) |
| Depends on | none |
| Can start | now |
| Write scope | repo root files (incl. `pyproject.toml`, which only F1 edits), `.github/workflows/ci.yml`, `.github/pull_request_template.md` (G2 and Q1 add their own workflow files), `.devcontainer/**`, `docker/**`, `src/gotauth/**/__init__.py` skeletons, `src/gotauth/py.typed`, `tests/test_smoke.py`, `changes/F1.*.md`, the folder READMEs below. plus `docs/requests/README.md` and `docs/ccr/README.md`; everything else under docs stays as it is |
| Allowed new deps | runtime: `pydantic>=2`, `httpx`, `cryptography`, `PyJWT` + the extras of CONTRACTS section 0. Dev groups: listed under Build |

## Goal
A clean clone builds and tests with one Docker command, and every later work package finds its folder, tooling, dependencies and CI ready. No auth code.

## Build
- `git init -b main`. `pyproject.toml`: `gotauth` 0.0.1, `src/` layout, hatchling, `requires-python = ">=3.11"`, MIT, core deps and extras exactly as CONTRACTS section 0 (incl. `starlette`), except the Phase 4 `flask` / `django` extras, which A3 and S2 add by request. `[project.scripts] gotauth = "gotauth.cli:main"`, `py.typed`.
- Every dev dependency the briefs allow goes in now, so no later work package edits `pyproject.toml`:
  - `dev`: pytest, pytest-asyncio, anyio, hypothesis, httpx, respx, aiosmtpd, pyright, ruff, poethepoet, towncrier, pip-audit (Q1).
  - `e2e`: playwright, pytest-playwright (Q2; browsers come from Q2's own Playwright image).
  - `docs`: mkdocs-material, mkdocstrings[python], tiktoken (G2; G2 requests a swap if it picks Zensical or needs a link checker).
  - Tests need the extras' packages: `uv sync --locked --all-extras` (AGENT-RULES) installs them for `poe check` and CI.
- Skeletons (docstring, `__all__ = []`, no extra imports): `contracts`, `crypto`, `core`, `email_password`, `sessions`, `social`, `email`, `storage/memory`, `storage/sqlalchemy`, `cli` (stub `main()` returning 1), `testing`, `checkup`, `integrations/{fastapi,asgi,mcp}`, `plugins/{api_key,two_factor,passkey,magic_link,organization,admin,oauth_provider,agent}`, `importers/fastapi_users`, plus parents. `gotauth/__init__.py`: `__version__` and a module `__getattr__` that lazily exports `GotAuth` (`gotauth.core`) and `AuthError`, `Principal`, `User`, `Session` (`gotauth.contracts`), per CONTRACTS 13.2.
- `docker/dev.Dockerfile`: `python:3.14-slim`; uv pinned via `COPY --from=ghcr.io/astral-sh/uv:<version> /uv /uvx /bin/`; Node 24 with `corepack enable` (pnpm pinned by each `package.json` `packageManager`; `COREPACK_ENABLE_DOWNLOAD_PROMPT=0`). Env `UV_PROJECT_ENVIRONMENT=/opt/venv`, `UV_CACHE_DIR`, `UV_LINK_MODE=copy`, pnpm store dir.
- `compose.yaml`: `dev` (repo at `/workspace`; named volumes for venv, uv cache, pnpm store; ports 4321, 5173, 3000, 8000; `GOTAUTH_TEST_POSTGRES_URL`, `GOTAUTH_TEST_REDIS_URL`; `depends_on` healthy), `postgres:17` (`pg_isready`), `redis:7` (`redis-cli ping`). `dev.sh` / `dev.ps1` = `docker compose run --rm dev "$@"` / `@args`. `.devcontainer/devcontainer.json` on the `dev` service.
- poethepoet: `format`, `lint` (ruff + text check), `types` (pyright), `test`, `vectors` (`pytest -m vectors`), `check` (format check + lint + types + test). ruff: py311, `E,F,I,UP,B,S,ASYNC,DTZ,T20,RUF`. pyright strict on `src`. pytest: `asyncio_mode = "auto"`, `--import-mode=importlib`; markers `vectors`, `slow` (F3), `timing` (Q1), `postgres`, `redis` (skip when the URL is unset); `poe test` ignores `tests/e2e` (Q2 runs it). Text check: small script failing on U+2013, U+2014 and emoji in `src/`, `tests/`, `docs/`.
- towncrier on `changes/` (`<WP-id>.<type>.md`; feature, bugfix, security, doc, removal).
- `.github/workflows/ci.yml`: lint + types; pytest on 3.11-3.14 with `postgres:17` and `redis:7` services; a no-extras job (`uv sync --no-dev`, import `gotauth` and the core modules); `uv build`. Actions pinned by commit SHA.
- Root: LICENSE (MIT), README (drop "No code yet", add quickstart), CONTRIBUTING (Docker, worktrees, Conventional Commits with `Refs: <WP>`, pinned versions), SECURITY.md stub, AGENTS.md = copy of `docs/plan/AGENT-RULES.md` with links rewritten to `docs/plan/...`, CLAUDE.md = `@AGENTS.md`, `.gitignore`, `.editorconfig`, `.gitattributes` (`* text=auto`, `*.sh text eol=lf`).
- Folder READMEs explaining the format: `registry/` (+ `package.json`), `apps/landing`, `apps/docs`, `examples/`, `spec/`, `tests/e2e`, `tests/security`, `changes/`, `docs/requests` (`<WP>-<topic>.md`: what, why, diff), `docs/ccr` (`<WP-id>-<topic>.md`, numbered by the integrator on acceptance). No root pnpm workspace: each Node project keeps its own lockfile inside its write scope.
- **Parallel-safe Docker** (AGENT-RULES 3):
  - `dev.sh` / `dev.ps1` set `COMPOSE_PROJECT_NAME` to the worktree folder name (lower-cased, e.g. `gotauth-c3`), so every worktree gets its own containers, venv volume, Postgres and Redis.
  - No service publishes host ports by default. `./dev.sh --ports <cmd>` adds `--service-ports` for human demos.
  - The uv cache may be one shared external volume (`gotauth-uv-cache`); uv's cache is safe for concurrent use. The venv volume is never shared.
- Commands in READMEs and CI use `uv sync --locked`. CI fails if `uv.lock` is out of date.
- CI also runs `python docs/plan/tools/verify_plan.py` (standard library only), so a plan edit that breaks parallel safety fails the build.
- `docs/ccr/README.md`: agents name files `<WP-id>-<topic>.md`; the integrator renames an accepted CCR to `<NNN>-<topic>.md`.
- Empty parent packages `src/gotauth/{plugins,integrations,storage,importers,interop}/__init__.py` and the final `src/gotauth/__init__.py` (lazy re-exports per CONTRACTS 13.2) are written once here and never edited by other work packages.

## Acceptance tests
- Clean clone: `./dev.sh uv sync --locked --all-extras && ./dev.sh uv run poe check` passes; same with `.\dev.ps1`.
- `tests/test_smoke.py` imports every skeleton; `import gotauth` works with no extras (CI job).
- `./dev.sh uv sync --locked --all-extras --group e2e --group docs` resolves.
- `./dev.sh uv build` makes wheel + sdist; the wheel has `gotauth/py.typed`.
- `./dev.sh node --version` / `pnpm --version` print pinned versions; Postgres and Redis reachable from `dev`.
- CI green on the first push.
- Two worktrees (`gotauth-a`, `gotauth-b`) run `./dev.sh uv run poe check` at the same time without sharing containers, volumes or ports (`docker compose ls` shows two projects).

## Out of scope
- Auth code (F2, F3 onward); release pipeline and attestations (Q1); landing page (G1).

## Notes
- pytest exits 5 when it collects nothing, so the smoke test is needed for `poe check`.
- For the owner, not the agent: after merge, publish a minimal real `gotauth 0.0.1` (README, license, metadata) to PyPI to claim the name. PEP 541 frowns on empty placeholders.
