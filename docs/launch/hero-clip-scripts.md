# Hero clip scripts

Three clips from the build plan. The owner records them; these are the shot lists.

**Common setup for every clip:**
- **Screen:** 1920x1080. Font size 18 pt in the editor and terminal, browser zoom 125%.
- **Hide:** `.env` files, terminal history, bookmarks bar, browser profile picture,
  notifications.
- **Never show:** a real API key, `GOTAUTH_SECRET`, an Anthropic key or a real email
  address. Use throwaway accounts made for the take.
- **Captions:** burn in the on-screen text below. Many viewers watch without sound.
- **Length:** under 60 seconds each, so they fit X, Bluesky, LinkedIn and Reddit
  without cuts.

## Clip 1: MCP login and revoke (about 50 seconds)

Follows "The clip" in [examples/fastmcp-server/README.md](../../examples/fastmcp-server/README.md);
keep the two in step.

**Prepare:**
1. Run the example as its README says, behind a tunnel: `cloudflared tunnel --url
   http://localhost:8000`, `BASE_URL` set to the tunnel's https URL, app restarted.
2. In Claude, add a custom connector with the URL `<BASE_URL>/mcp`. Do not connect yet.
3. Delete `app.db` and run `uv run gotauth migrate --auth app.auth:auth`, so the take
   starts with no users.
4. Layout: Claude on the left, the app's browser window on the right.

| Time | On screen | Caption |
|---|---|---|
| 0-4s | `app/auth.py`: the `oauth_provider(mcp=True, ...)` block | Your FastAPI app is the OAuth server |
| 4-12s | Claude: "List my projects." Claude asks to connect; the browser shows the sign-in page; create an account | Claude signs in on your page, in your user table |
| 12-17s | The consent page for `projects:read`; Allow | You choose what the client gets |
| 17-22s | Claude lists the three demo projects | The tool knows who the user is |
| 22-32s | "Create a project called Launch." The server answers 403; Claude asks for `projects:write`; the consent page shows the extra scope; Allow; the project is created | Missing scope: the client asks for more |
| 32-42s | In the app, "Connected apps", revoke Claude | The user revokes the app |
| 42-50s | Claude: "List my projects." The call fails and Claude asks to connect again | The next call is a 401 |

**End card:** `pip install "gotauth[fastapi,mcp,sqlalchemy,sqlite]"` and the repo URL.

## Clip 2: the same prompt with and without GotAuth's skill (about 45 seconds)

Uses the agent-install harness, [scripts/agent-install-test](../../scripts/agent-install-test/README.md).
The numbers on screen come from `agent-baseline.md` and the harness's `summary.md`,
and from nothing else.

**Prepare:**
1. Run `scripts/agent-install-test/run.sh --runs 1` and `run.sh --baseline --runs 1` with
   your own `ANTHROPIC_API_KEY` (never on screen; set it before recording).
2. Keep both `results/<time>-*/run-1/` folders: `diff.patch`, `check.txt` and the
   transcript.
3. Record each run's terminal, or replay the transcripts at speed. Say on screen that
   the video is sped up.
4. Scan the transcripts for secrets before showing any of them.

| Time | On screen | Caption |
|---|---|---|
| 0-5s | Split screen, the same fresh FastAPI app on both sides and the prompt "Add email + password and GitHub login and API keys to this FastAPI app." | Same app, same prompt |
| 5-20s | Both agents working, sped up. Left: no skill. Right: GotAuth's skill | Left: no skill. Right: GotAuth's skill |
| 20-30s | Left: the diff, scrolling. Right: the diff | [pending measurement: lines of app code added, each side] |
| 30-40s | Both `check.txt` results side by side | [pending measurement: checker verdict, each side] |
| 40-45s | Left: `uvx gotauth check` on the left app; its score | [pending measurement: score] |

Do not put any number on screen that is not in `agent-baseline.md` or `summary.md`. If
the run without the skill also passes the checker, say so: the clip is then about the
amount of code, not about correctness.

## Clip 3: `uvx gotauth check` (about 30 seconds)

Runs on the seeded hand-rolled app in
[scripts/agent-install-test/checker/fixtures/bad_app](../../scripts/agent-install-test/checker/fixtures/bad_app/app/main.py)
(passlib, python-jose, HS256 with a 9-character literal secret, an unthrottled `/login`).
The output below was recorded from this repository on 2026-10-16.

**Prepare:** copy `bad_app` and `good_app` from the fixtures folder to a scratch folder,
so the paths on screen are short. Clear the terminal.

| Time | On screen | Caption |
|---|---|---|
| 0-6s | `app/main.py` of the hand-rolled app: the `jose` and `passlib` imports, `SECRET = "change-me"` | Auth the way agents often write it |
| 6-16s | `uvx gotauth check bad_app` | No install, no network, no account |
| 16-22s | The findings and the score, held still | 3 high, 1 medium. Score 49/100 |
| 22-30s | `uvx gotauth check good_app`, a small FastAPI app whose auth is GotAuth: "no findings", "Score: 100/100" | Every finding comes with a fix |

**Output for the 16-22s shot** (from `gotauth check` on 2026-10-16; shorten the `fix:`
lines on screen if they wrap):

```text
bad_app/app/main.py
  6:1    high    GA002  python-jose is imported; releases before 3.4.0 are affected by CVE-2024-33663 and CVE-2024-33664.
  7:1    high    GA001  passlib is imported; its last release is 1.7.4 (October 2020).
  21:2   medium  GA007  POST route "/login" looks like a sign-in endpoint and the project has no rate limiter.
  25:13  high    GA003  jwt.encode signs HS256 tokens with a hard-coded 9-character secret.

Scanned 3 files: 4 findings (3 high, 1 medium, 0 low).
Score: 49/100
```

Run it again on the day of recording. If the output differs, film what it prints now.
