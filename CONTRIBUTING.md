# Contributing to GotAuth

GotAuth is built as work packages that run in parallel, often by coding agents. The rules every contributor follows are in [AGENTS.md](AGENTS.md); the engineering plan and the work-package briefs are in [docs/plan/](docs/plan/README.md). This file covers the practical side: the dev container, worktrees, commits and pinned versions.

## Dev container

All Python and Node tooling (`uv`, `python`, `pytest`, `ruff`, `pyright`, `pnpm`, `node`) runs in Docker. Do not create a virtual environment or run `pip`, `uv` or `pnpm install` on the host: the virtual environment lives in a Docker volume and `node_modules` folders hold Linux binaries. Git runs on the host.

```bash
./dev.sh uv sync --locked --all-extras     # install everything the tests need
./dev.sh uv run poe check                  # format check, lint, types, tests
./dev.sh uv run pytest tests/sessions -q   # any command runs in the container
./dev.sh pnpm --dir registry install --frozen-lockfile
./dev.sh                                   # interactive shell
```

On Windows, `./dev.sh` works in Git Bash and `.\dev.ps1` takes the same arguments in PowerShell. Both wrappers run `docker compose run --rm dev <command>` from the repository folder and accept these options before the command:

| Option | Effect |
|---|---|
| `--ports` | Publish the dev server ports 3000, 4321, 5173 and 8000 on `127.0.0.1` (`--service-ports`). For demos only; dev servers must listen on `0.0.0.0` |
| `--build` | Rebuild the image first. Needed after `docker/` changes, because Compose reuses an existing image |
| `--down` | Stop and remove this worktree's containers. Volumes are kept |

What the container provides:

- the repository mounted at `/workspace`, working as the non-root user `dev`
- the virtual environment in `/opt/venv` (`UV_PROJECT_ENVIRONMENT`), a volume per worktree
- Postgres and Redis services; the tests find them through `GOTAUTH_TEST_POSTGRES_URL` and `GOTAUTH_TEST_REDIS_URL`
- the uv cache and the pnpm store in the shared volumes `gotauth-uv-cache` and `gotauth-pnpm-store`, which the wrappers create on first use. Both tools support concurrent use of their cache

The first run builds the image (about a minute) and fills the uv cache (several minutes on a slow connection). Later runs start in a few seconds.

On Linux hosts whose user id is not 1000, build the image with your ids so the container can write to the repository: `GOTAUTH_UID=$(id -u) GOTAUTH_GID=$(id -g) ./dev.sh --build`.

VS Code users can open the repository with Dev Containers instead (`.devcontainer/devcontainer.json`, same image and services, no published ports).

## Tasks

| Command | What it runs |
|---|---|
| `./dev.sh uv run poe format` | `ruff format .` |
| `./dev.sh uv run poe format-check` | `ruff format --check .` |
| `./dev.sh uv run poe lint` | `ruff check .`, then `scripts/check_text.py` (fails on en dashes, em dashes and emoji in `src/`, `tests/`, `docs/` and root Markdown files) |
| `./dev.sh uv run poe types` | `pyright`: strict on `src/`, standard on `tests/` |
| `./dev.sh uv run poe test` | `pytest`, without `tests/e2e` and without tests marked `timing` |
| `./dev.sh uv run poe vectors` | `pytest -m vectors` (spec vectors) |
| `./dev.sh uv run poe check` | format check, lint, types and test, in that order. CI runs the same steps |

Extra arguments go to the underlying command, for example `./dev.sh uv run poe test tests/crypto -q`.

### Test markers

| Marker | Meaning |
|---|---|
| `vectors` | Spec vectors from `spec/` |
| `slow` | Slow tests, for example full-cost password hashing. They run in `poe test` |
| `timing` | Timing comparisons. Not part of `poe test`; work package Q1 runs them in their own CI job |
| `postgres` | Needs `GOTAUTH_TEST_POSTGRES_URL`. Skipped when it is not set |
| `redis` | Needs `GOTAUTH_TEST_REDIS_URL`. Skipped when it is not set |

The skip for `postgres` and `redis` lives in the root `conftest.py`. Shared fixtures belong in `tests/conftest.py` (work package F2) and area fixtures in `tests/<area>/conftest.py`. pytest runs with `--import-mode=importlib`, so test files in different folders may share names. Browser tests in `tests/e2e` (work package Q2) run in their own image.

## Worktrees and parallel work

One work package is one branch and one git worktree. Each worktree folder is its own Compose project (the wrappers set `COMPOSE_PROJECT_NAME` to the lower-cased folder name), so it gets its own dev container, virtual environment, Postgres and Redis, and no ports are published by default. Several worktrees can run `poe check` at the same time.

```bash
git worktree add ../gotauth-c3 -b wp/c3-sessions
cd ../gotauth-c3 && ./dev.sh uv sync --locked --all-extras
docker compose ls                          # one project per active worktree
```

When a worktree is done:

```bash
./dev.sh --down                            # inside the worktree
docker volume rm gotauth-c3_venv gotauth-c3_cache
git worktree remove ../gotauth-c3
```

## Dependencies and lockfiles

- Only work package F1 edits `pyproject.toml` and `uv.lock`. Anyone else who needs a dependency files `docs/requests/<WP>-<topic>.md` (see [docs/requests/README.md](docs/requests/README.md)).
- Install with `uv sync --locked`, which fails instead of rewriting `uv.lock`. CI does the same, so an outdated lockfile fails the build.
- Extra dependency groups: `--group e2e` (Playwright) and `--group docs` (docs site).
- Node projects keep their own lockfiles; see the next section.

## Node projects

A Node project is a folder with a `package.json` at one of these places:

- `registry/`
- `apps/<name>/`, for example `apps/landing/` or `apps/docs/`
- `examples/<name>/` or `examples/<name>/<part>/`, for example `examples/fastapi-nextjs/frontend/`

Every Node project follows the same rules, so CI can treat them alike:

- It has its own `pnpm-lock.yaml`. There is no root pnpm workspace.
- Its `package.json` pins `"packageManager": "pnpm@12.8.1"`, the version in the dev image.
- It exposes a `check` script that runs whatever applies to it: lint, type check, tests and build. For example: `"check": "pnpm lint && tsc --noEmit && vitest run && pnpm build"`. Checks that compare a project with the Python side, such as the registry's OpenAPI drift check, belong in `check` too.
- It installs with `pnpm install --frozen-lockfile` outside your own write scope.

CI's `node` job finds every Node project and runs `pnpm install --frozen-lockfile`, then `pnpm run --if-present check`, in each one with the pinned Node and pnpm versions. Run the same thing locally before you push:

```bash
./dev.sh pnpm --dir registry install --frozen-lockfile
./dev.sh pnpm --dir registry run --if-present check
```

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/), small and focused, with the work-package ID as a trailer:

  ```text
  feat(sessions): hash session tokens at rest

  Refs: C3
  ```

- No AI co-author or "Generated with" lines in commits or pull requests.
- Rebase on `main` before opening the pull request, and fill in the template.
- If you changed published code, add a news fragment (see [changes/README.md](changes/README.md)).

## Writing style

Code, comments, docs and commit messages use plain ASCII punctuation (`->`, `>=`, `...`), no emoji or decorative symbols, no en or em dashes, and plain technical wording. `poe lint` checks the dashes and emoji. Tests that need such characters as data write them as escapes, for example `"\u2014"`.

## Pinned versions

| Tool | Version | Where it is pinned |
|---|---|---|
| Python (dev image) | 3.14.8 | `docker/dev.Dockerfile` |
| Python (CI) | 3.11, 3.12, 3.13, 3.14 | `.github/workflows/ci.yml` |
| uv | 0.12.22 | `docker/dev.Dockerfile`, `.github/workflows/ci.yml` |
| Node | 24.21.0 | `docker/dev.Dockerfile` |
| pnpm | 12.8.1 | `docker/dev.Dockerfile` and each `package.json` (`packageManager`) |
| Postgres | 17 | `compose.yaml`, `.github/workflows/ci.yml` |
| Redis | 7 | `compose.yaml`, `.github/workflows/ci.yml` |
| ruff, pyright, pytest and every other Python package | exact versions | `uv.lock` |
| GitHub Actions | commit SHAs | `.github/workflows/ci.yml` |

To update the dev image, change the versions in `docker/dev.Dockerfile` (and the places listed above), then run `./dev.sh --build uv run poe check`.
