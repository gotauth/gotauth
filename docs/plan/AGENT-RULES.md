# Rules for every agent working on GotAuth

> Work package F1 copies this file to the repo root as `AGENTS.md` (and creates `CLAUDE.md` containing `@AGENTS.md`). Every agent reads **only three files** before starting:
> 1. this file
> 2. [CONTRACTS.md](CONTRACTS.md)
> 3. its own work-package brief in [`wp/`](wp/)

## 1. Stay in your lane
- **Write only inside your work package's "Write scope".** You may read anything.
  - Every work package also owns its tests in `tests/<area>/**` and its news fragments `changes/<WP-id>.*.md`.
  - Only F1 edits `pyproject.toml` and `uv.lock`; F1 adds every dev dependency the briefs allow. Anything else needs a request file.
- **Files no agent edits after they exist:**

  | Files | Owner |
  |---|---|
  | `pyproject.toml`, `uv.lock`, `.github/workflows/ci.yml`, `src/gotauth/__init__.py` and the empty parent packages (`plugins/`, `integrations/`, `storage/`, `importers/`) | F1 |
  | `src/gotauth/contracts/**` and `tests/conftest.py` | F2, frozen at M0 |
  | `docs/plan/**` | the owner and integrator only (status table, briefs, contracts) |
- **Need a change outside your scope?** Don't make it, even to fix a bug you found in someone else's module. Add a request file `docs/requests/<your-WP>-<topic>.md` (what, why, proposed diff) and continue with a local stub or the testing kit.
- **Never edit `src/gotauth/contracts/**` after M0.** To change a contract, write `docs/ccr/<your-WP>-<topic>.md` (a contract change request) and stop work that depends on it. The integrator numbers it when accepting it (`docs/ccr/<NNN>-<topic>.md`), so two parallel agents never pick the same number, and bumps `CONTRACT_VERSION`.
- **Never import another work package's module** except these:
  - `gotauth.contracts`, `gotauth.testing` and `gotauth.crypto`
  - the public helpers in CONTRACTS 13.2
  - for integrations, `GotAuth` itself

  Plugins talk to each other only through `ctx.auth.api.call(...)` with the CONTRACTS 12.5 shapes, after checking `ctx.auth.plugin_ids`.
- Don't reformat, rename or "tidy" files you don't own.

## 2. Never wait for another work package
- **Build against the interfaces in CONTRACTS.md and the testing kit `gotauth.testing`:**
  - `memory_adapter()`
  - `fake_clock()`
  - `seq_ids()`
  - `fake_mailer()`
  - `fake_oauth_provider()`
  - `make_auth()`
  - `make_client()`
  - `fake_sessions()`
  - `make_context()`
  - `call_endpoint()`
  - `stub_resolver()`
  - `stub_plugin()`
  - `fresh_database_url()`
  - `adapter_conformance()`
  - `load_vectors()`
- **If a module you depend on is still a stub,** test against the kit and leave a `# TODO(<WP-id>): switch to real <module> after merge` note.
- **Test in two layers:**
  - **Unit:** handlers through `make_context()` / `call_endpoint()`. These work from M0.
  - **HTTP round trip:** through `make_auth()` / `make_client()`. These work once C1 has merged. Before C1 or the core modules merge, mark round-trip tests with `pytest.importorskip` or a skip that names the missing work package. Never block on them.

## 3. Branch, worktree, pull request
- **One work package = one branch = one git worktree:**
  ```bash
  git worktree add ../gotauth-<wp> -b wp/<wp-id>-<slug>
  cd ../gotauth-<wp> && ./dev.sh uv sync --locked --all-extras
  ```
- **Each worktree is isolated in Docker.** `dev.sh` uses the worktree folder name as the Compose project name, so every agent gets its own:
  - container
  - virtual environment volume
  - Postgres and Redis

  No service publishes host ports by default, so parallel agents never collide on ports. Only `./dev.sh --ports ...` publishes them, for demos run by a human.
- **Lockfiles are read-only for agents:**
  - Use `uv sync --locked`, which fails instead of rewriting `uv.lock`.
  - Use `pnpm install --frozen-lockfile`, except in a Node project inside your own write scope, where you may add dependencies the brief allows.
- **Small commits** using [Conventional Commits](https://www.conventionalcommits.org/), with the work-package ID as a trailer. Example: `feat(sessions): hash session tokens at rest` followed by `Refs: C3`.
- **Never add AI co-author or "Generated with" lines** to commits or PRs.
- Open one PR per work package, and fill in its checklist.
- **Rebase on `main` before you open the PR.** Resolve conflicts only inside your write scope.

## 4. Definition of done (every work package)
- [ ] Every **acceptance test** in the brief passes.
- [ ] `./dev.sh uv run poe check` is green: ruff format check, ruff lint, pyright strict and pytest, including the `spec/` vectors that apply.
- [ ] All public functions, classes and methods have Google-style docstrings. Your module has a short `README.md` with a copy-paste example.
- [ ] A towncrier news fragment is added in `changes/` (`<WP-id>.<type>.md`, e.g. `C3.feature.md`) if you changed published code.
- [ ] No new runtime dependency unless the brief allows it. Optional dependencies go behind an extra and are imported lazily.
- [ ] The PR description lists: what was built, what was stubbed, any request or CCR files, and any framework API differences you found.

## 5. Engineering rules
- **Fail closed.** If in doubt, deny. Any unexpected exception in an authentication or authorization path becomes `AuthError("INTERNAL_ERROR", 500)` and never grants access.
- **Secrets at rest:**
  - Session tokens, API keys, verification tokens and OAuth codes/tokens are **stored hashed** (SHA-256 of the token). The raw value is only ever returned once, to its owner.
  - Passwords use the crypto kit's password hashing only.
- **Constant-time comparison** (`hmac.compare_digest`) for every secret, signature or hash comparison.
- **Secrets never appear** in logs, exception messages, error responses, audit data or `repr()`. Use `SecretStr` or redact.
- **No state change on HTTP GET.** The only exceptions:
  - OAuth redirect callbacks and one-time email links (verify email, magic link), both protected by single-use tokens and state
  - `GET /oauth2/authorize` issuing a code when consent is already stored (CONTRACTS 12.3)
  - sliding session refresh on `GET /session` (bookkeeping)
- **No account enumeration.** Sign-up, sign-in, password reset and magic-link endpoints return the same response shape and similar timing whether or not the account exists.
- **Deterministic tests:** inject `Clock` and `IdGenerator`. Never call `datetime.now()`, `time.time()`, `uuid4()` or `secrets.*` directly in library code. Go through `ctx.clock`, `ctx.ids` and the crypto kit.
- **Async-first.** Library code is `async def`, with no blocking I/O in the event loop. CPU-heavy password hashing runs through `anyio.to_thread` / `asyncio.to_thread` (the crypto kit handles this).
- **Typing:** pyright strict passes; no `Any` in public signatures without a comment explaining why; Pydantic v2 models for every HTTP input and output.
- **Property tests ([Hypothesis](https://hypothesis.readthedocs.io))** for anything with an invariant: token round trips, single use, cookie signing, hashing, scope narrowing, rate-limit windows.
- **No framework imports** in `src/gotauth/contracts`, `core`, `crypto`, `sessions`, `email_password`, `social` or `plugins/*`. Framework code lives only in `integrations/*`.
- **Writing style (code, comments, docs, commits):**
  - no emojis or decorative symbols, no em dashes
  - plain ASCII punctuation (`->`, `>=`, `...`)
  - plain technical wording without marketing filler
  - comments explain *why*, not *what*
- **Follow the framework's current docs over the brief.** Briefs describe framework and spec versions as of 2026-10. If the docs differ, follow the docs and say so in the PR. Record the targeted versions in your module README.

## 6. Run every command in Docker
- **The host has no Python or Node toolchain.** All `uv`, `python`, `pytest`, `ruff`, `pyright`, `pnpm` and `node` commands run in the dev container (Python 3.14 + pinned uv, Node 24 + pinned pnpm, plus Postgres and Redis services):
  ```bash
  ./dev.sh uv sync --locked --all-extras   # PowerShell: .\dev.ps1 uv sync --locked --all-extras
  ./dev.sh uv run poe check            # format check + lint + types + tests
  ./dev.sh uv run pytest tests/sessions -q
  ./dev.sh pnpm --dir registry build
  ```
- **Never create a virtual environment or run `pip`/`uv` on the host.** The `.venv` lives in a Docker volume and holds Linux binaries.
- **Git runs on the host.** Worktrees work too: run `./dev.sh ...` from inside each worktree folder (each one mounts its own folder).

## 7. Tooling (set up by F1)
| Need | Tool |
|---|---|
| Runtime (dev) | Python 3.14 in Docker (`docker/dev.Dockerfile`, `compose.yaml`); CI matrix 3.11-3.14 |
| Packaging / environments | uv (workspace root `pyproject.toml`, `uv.lock`), build backend hatchling |
| Tasks | poethepoet (`poe check`, `poe test`, `poe lint`, `poe types`, `poe vectors`) |
| Test | pytest + pytest-asyncio (or anyio) + Hypothesis + httpx (ASGI transport) |
| Lint / format | ruff |
| Types | pyright (strict) |
| Changelog | towncrier |
| Databases in tests | SQLite (aiosqlite) always; Postgres (asyncpg) via the compose service |
| UI registry, landing, docs | Node 24 + pnpm in the same container |
| CI | GitHub Actions: ruff, pyright, pytest on 3.11-3.14, spec vectors, Postgres service |

## 8. Who merges
The **integrator** merges in dependency order and runs the end-to-end example after each merge. This is the human owner, or one designated "integrator agent". Agents never merge their own PRs.
