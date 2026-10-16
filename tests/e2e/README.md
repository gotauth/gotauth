# End-to-end tests

Real-browser and protocol tests against the example apps. Work package Q2.

| Test | What it proves |
|---|---|
| `test_browser_flows.py` | On `examples/fastapi-nextjs` in Chromium: sign up, verify the email from the console, sign in and out; two-factor setup and the sign-in challenge; passkey registration and usernameless sign-in with a CDP virtual authenticator; an API key that works for a script and stops when revoked; an organization invitation from email to membership |
| `test_mcp_flow.py` | On `examples/fastmcp-server` with real servers: the 401 and RFC 9728 metadata, RFC 8414 metadata at the host root, authorization code with PKCE and `resource`, sign-up and consent in the browser, the token request, a tool call, the token's audience (`aud` is the MCP server's URL, RFC 8707), refresh rotation, revocation in "Connected apps" ending access at once, and a second server instance refusing the token |

## Run

Needs Docker. From the repository root:

```bash
tests/e2e/run.sh              # one run on fresh containers
tests/e2e/run.sh --repeat 3   # three runs in a row (the acceptance rule)
tests/e2e/run.sh -- -k mcp    # pytest arguments after "--"
```

`compose.yaml` builds the example's own backend and frontend images, and the test
runner (`Dockerfile`: the official Playwright Python image, version equal to
`playwright` in `uv.lock`, with the repository's `e2e` dependency group). The runner
shares the frontend's network, so the browser uses `http://localhost:3000`, the
backend's `BASE_URL`. That keeps cookies, the `Origin` check, the console email sender
and passkeys (which need localhost on plain http) on their real paths. The backend's
console output, where GotAuth prints emails, goes to a shared log the tests read. The
MCP example runs inside the runner, on ports 8000 and 8001.

Every test browser reaches the backend through the frontend's proxy, so all sign-ins
come from one address and GotAuth's per-address rate limits would stop the suite. The
compose file sets `GOTAUTH_RATE_LIMIT=off`, which the example honours only when its
`BASE_URL` is on localhost. When a run fails, `run.sh` prints the frontend's log and
the backend's before removing the containers.

## Rules

- Tests wait on page state or poll a condition with a timeout; never a fixed sleep.
- Every test makes its own users (`new_email()`), so tests don't depend on each other.
- `poe test` and `poe check` skip this folder (`--ignore=tests/e2e`), and pyright excludes
  it: the default environment has no Playwright. `.github/workflows/e2e.yml` runs it.
