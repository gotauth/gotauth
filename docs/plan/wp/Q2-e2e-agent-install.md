# Q2: E2E tests + agent-install test

| | |
|---|---|
| Lane / wave | Quality / **Wave 3** |
| Size | M |
| Depends on | G4 (`examples/fastapi-nextjs`; part 2 for the 2FA, passkey and org tests), G2 (skill, llms.txt); O2 (`examples/fastmcp-server`) for the MCP test |
| Can start | e2e after M2 (part 2 tests once G4 part 2 merges); agent-install once G2's skill draft exists |
| Write scope | `tests/e2e/**`, `scripts/agent-install-test/**`, `docs/launch/agent-baseline.md`, `changes/Q2.*.md` |
| Allowed new deps | dev only: `playwright`, `pytest-playwright` (added up front by F1) |

## Goal
Prove GotAuth works the way users and coding agents meet it: real-browser flows on the example app, a scripted MCP OAuth flow, and a coding agent that installs GotAuth correctly from the skill in 3 of 3 runs.

## Build
- `tests/e2e/`: Python Playwright (Chromium) in Docker (`tests/e2e/Dockerfile` from the official Playwright Python image, `tests/e2e/run.sh`), against `examples/fastapi-nextjs` with the console email sender:
  - sign up -> verification link read from the server's console output -> sign in -> sign out.
  - 2FA: enable, take the secret from the otpauth URI, compute codes with the crypto kit, answer the sign-in challenge.
  - passkey: CDP `WebAuthn.enable` + `WebAuthn.addVirtualAuthenticator` (ctap2, internal, resident key, user verification); register, then usernameless sign-in.
  - API key: create in the UI, call a protected route with httpx -> 200; revoke -> 401.
  - org invitation: A creates an org and invites B; B accepts from the console email and sees the org.
- `tests/e2e/test_mcp_flow.py` on `examples/fastmcp-server`, scripted httpx client: 401 + `WWW-Authenticate` -> RFC 9728 metadata -> RFC 8414 metadata at the host root (`/.well-known/oauth-authorization-server/api/auth`, served by `auth.well_known()`) -> authorize (PKCE S256, `resource`) -> sign in + consent -> token (form body) -> MCP tool call with Bearer -> refresh rotation -> revoke in the app -> 401 on the next call (same process, 12.2).
- `scripts/agent-install-test/`:
  - `Dockerfile` (Node, Claude Code CLI, Python, uv) and `template/`, a fresh FastAPI app with one test.
  - `run.sh`: copy the template, add `.claude/skills/gotauth/SKILL.md` (from `skills/`) and `llms.txt`, run Claude Code headless (`claude -p "Add email + password and GitHub login and API keys to this FastAPI app"`, non-interactive permission mode, explicit allowed tools), save the transcript and the diff.
  - `checker/` (pytest on the result): `gotauth` is a dependency; no `passlib`, `python-jose` / `jose`, direct `bcrypt` or hand-written JWT code in the app; the app starts; sign-up and sign-in work; `sign_in_social` for `github` returns a GitHub authorize URL with `state` and `code_challenge`; an API key authenticates a protected route; the app's own tests pass.
  - Pass rule: 3 of 3 runs green. `--baseline` runs the same prompt without skill and llms.txt and writes `docs/launch/agent-baseline.md`: auth lines of code added, libraries used, checker results, model, CLI version, date.
- Credentials: the owner supplies their own Claude credentials as environment variables at run time. Never in the image, logs, transcripts or git; `run.sh` refuses to start if a credential file is in the build context.

## Acceptance tests
- E2E suite passes 3 consecutive Docker runs with no fixed sleeps.
- MCP test passes, and fails when the token's `resource` is another server.
- Checker fails on a seeded passlib + python-jose app and passes on a seeded correct GotAuth app.
- Agent-install 3/3 on the final run before M3; transcripts attached to the PR after a secret scan.
- `agent-baseline.md` contains only measured values with the run date.

## Out of scope
Unit and security tests (module WPs, Q1), the example apps (G4, O2), skill content (G2), using the baseline in posts (G5).

## Notes
- Check the current Claude Code headless flags (`-p`, `--output-format`, `--permission-mode`, `--allowedTools`) and project skill loading; record the CLI version.
- Virtual authenticators work only in Chromium through CDP.
- CIMD rejects loopback hosts (12.3), so the MCP test uses the static client O2's example seeds.
- The 2FA, passkey and org-invitation tests depend on G4 part 2 (after P2, P3, P5); G4 keeps those steps scriptable.
