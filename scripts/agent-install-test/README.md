# Agent-install test

Does a coding agent add auth to an app with GotAuth, correctly, when it has GotAuth's
skill? Claude Code gets a fresh FastAPI app (`template/`) and the prompt "Add email +
password and GitHub login and API keys to this FastAPI app.", with
`.claude/skills/gotauth/SKILL.md` (from `skills/`) and `llms.txt` (from the docs build)
in the project. `checker/` then judges the result. Work package Q2.

**Pass rule:** 3 of 3 runs pass the checker.

## Run

Needs Docker and one credential of your own, either of:
- **A Claude subscription token** (Pro, Max, Team or Enterprise). Run `claude setup-token`
  on your machine, approve in the browser, and copy the token it prints (valid for a
  year; it is not saved anywhere). Runs count against your subscription's usage.
- **An Anthropic API key** (`ANTHROPIC_API_KEY`), billed per use.

Set only one. `run.sh` refuses to start without a credential, with both set, with a
value that does not look like one (`sk-ant-...`, no spaces or line breaks), or with a
file that looks like a credential (`.env*`, `*.pem`, `*.key`, `.credentials.json`,
`.claude.json`) anywhere in this folder.

**On Windows**, run it from Git Bash, with Docker Desktop running. `read -rs` reads the
token without showing it or saving it in the shell history:

```bash
read -rs CLAUDE_CODE_OAUTH_TOKEN && export CLAUDE_CODE_OAUTH_TOKEN   # paste, then Enter
scripts/agent-install-test/run.sh --runs 1    # one run first, to see that it works
scripts/agent-install-test/run.sh             # 3 runs with the skill
scripts/agent-install-test/run.sh --baseline  # the same prompt without skill and llms.txt
unset CLAUDE_CODE_OAUTH_TOKEN                  # when you are done
```

From PowerShell, call Git Bash by its full path, so the variable reaches it (a plain
`bash` may start WSL, which does not see it):

```powershell
# Masked as you paste, and kept out of the history and the screen.
$secure = Read-Host "Token" -AsSecureString
$env:CLAUDE_CODE_OAUTH_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
& "C:\Program Files\Git\bin\bash.exe" scripts/agent-install-test/run.sh --runs 1
Remove-Item Env:CLAUDE_CODE_OAUTH_TOKEN
```

The `--baseline` run writes `docs/launch/agent-baseline.md`; commit it in a pull request.

### Where the credential goes

- **Never in the image, the container's environment or `docker inspect`:** `run.sh`
  sends it on the container's standard input, and only the `claude` process gets it as
  an environment variable.
- **Gone before the checker runs:** after the agent's session, every process the agent
  left running is ended and the credential is dropped, before `uv sync`, the checker,
  the app and its tests run. During the session it is not gone: see "What the agent
  can see" below.
- **Never in the results:** the files are scanned twice with the same `scan.sh`, inside
  the container (as their owner) and again on the host, for the credential itself and
  for anything shaped like a key or token, in file contents and file names. A match deletes the run's files, fails the run and prints a warning. The scans fail
  closed: a file that cannot be read counts as a match (this needs GNU or BSD grep, as
  in Git Bash, Linux and macOS; BusyBox grep flags every run). Ctrl-C stops the
  container and scans what was written.
- **Not in the process list or traces:** the scans read the credential from standard
  input, and `run.sh` turns off `set -x`.

### What the agent can see

During its session the agent runs `uv`, `python` and the like, and those commands
inherit the credential from the `claude` process, as in any CI job that runs Claude
Code. A package the agent installs could read it. Claude Code can scrub credentials
from its commands (`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`), but that needs bubblewrap, which
cannot create namespaces in a default Docker container, and loosening the container to
allow it would be the worse trade. So run this only on the template here, and if a run
ever looks wrong, treat the credential as exposed: delete an API key in the Claude
Console; for a subscription token, look in your Claude account settings for a way to
revoke it, or ask Anthropic support.

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
