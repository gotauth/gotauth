# Agent-install test

Does a coding agent add auth to an app with GotAuth, correctly, when it has GotAuth's
skill? Claude Code gets a fresh FastAPI app (`template/`) and the prompt "Add email +
password and GitHub login and API keys to this FastAPI app.", with
`.claude/skills/gotauth/SKILL.md` (from `skills/`) and `llms.txt` (from the docs build)
in the project. `checker/` then judges the result. Work package Q2.

**Pass rule:** 3 of 3 runs pass the checker.

## Run

Needs Docker and your own Anthropic API key. The key is passed to the container at run
time only (`docker run -e ANTHROPIC_API_KEY`), and only Claude Code sees it: it is unset
before the agent's dependencies are installed and the app, the checker and the app's
tests run. It is never in the image, and a run whose files contain the key, or anything
that looks like one, is deleted and counts as failed.

```bash
export ANTHROPIC_API_KEY=...                  # yours; never commit it
scripts/agent-install-test/run.sh             # 3 runs with the skill
scripts/agent-install-test/run.sh --baseline  # the same prompt without skill and llms.txt
scripts/agent-install-test/run.sh --runs 1    # one run, while trying things
```

Each run costs model usage. `run.sh` refuses to start without a key, or with a file that
looks like a credential (`.env*`, `*.pem`, `*.key`, `.credentials.json`, `.claude.json`)
anywhere in this folder.

## What happens in a run

1. A wheel is built from this checkout and mounted at `/wheels`. With the skill,
   `run.sh` maps `gotauth` to it in the app's `pyproject.toml` (`[tool.uv.sources]`),
   standing in for a current release on PyPI. The baseline app has no such hint.
2. The template is committed in a fresh git repository, so the agent's changes become
   `diff.patch`.
3. Claude Code runs headless: `claude -p "<prompt>" --output-format stream-json --verbose
   --permission-mode acceptEdits --max-turns 80`, allowed to read and edit files and to
   run `uv`, `uvx`, `python`, `ls`, `cat` and `mkdir`. Project skills in
   `.claude/skills/` are loaded by Claude Code itself. The CLI version is pinned in the
   `Dockerfile` (2.1.287, released 2026-10-01).
4. `checker/check.py` judges the app.

Results go to `results/<time>-<skill|baseline>/run-N/`: `transcript.jsonl`,
`diff.patch`, `check.txt`, `check.json`; and `summary.md` for all runs. `results/` is
ignored by git. Scan transcripts for secrets before attaching them anywhere.

## The checker

`checker/check.py APP_DIR` (exit code 0 when every check passes):

| Check | How |
|---|---|
| `gotauth` is a dependency | `pyproject.toml` |
| No hand-written auth code | No `passlib`, `pwdlib`, `jose`, `jwt`, `joserfc`, `jwcrypto`, `authlib`, `bcrypt`, `argon2` or `itsdangerous` import, and no `hashlib.pbkdf2_hmac` or `hashlib.scrypt` however imported, in the app's code (tests excluded; relative imports of the app's own modules are fine) |
| `gotauth check` finds nothing of high severity | The scanner from `gotauth.checkup` |
| The app starts | `probe.py` imports the first FastAPI app in `app/main.py`, `main.py` or `app/__init__.py`, and finds the `GotAuth` object; `gotauth migrate` creates its tables when it uses SQLAlchemy |
| Sign-up, verification and sign-in work | Over ASGI; the verification link comes from the console email |
| GitHub sign-in starts | `POST .../sign-in/social` gives a `github.com` authorize URL with `state` and `code_challenge` |
| An API key gets through a protected route | A key from `POST .../api-keys` gets a 200 from a GET route that refuses anonymous callers (with the scopes the route asks for), and a made-up key is refused there |
| The app's own tests pass | `pytest` in the app |

The probe runs the app's lifespan, and sets `GOTAUTH_SECRET`, `GITHUB_CLIENT_ID`,
`GITHUB_CLIENT_SECRET`, `DATABASE_URL` and `BASE_URL` when neither the environment nor
the app's `.env` does. A command that runs over 10 minutes counts as a failed check. `checker/tests/` runs the checker on
two seeded apps: a hand-written passlib and python-jose app fails, and a correct GotAuth
app passes. Run it with `./dev.sh uv run pytest scripts/agent-install-test/checker/tests`.

## The baseline

`--baseline` runs the same prompt without the skill and `llms.txt`, and writes
`docs/launch/agent-baseline.md` with measured values only: the checker's verdict per
run, lines of app code added, libraries added, the model, the CLI version and the date
(`report.py`).
