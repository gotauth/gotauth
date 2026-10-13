# OpenID conformance runs

The OpenID Foundation conformance suite tests O1 as an OpenID provider. Results go in `O1-<date>.md` next to this file. Every failure is triaged there as one of: fix (with a request file), accepted (with the reason), or suite issue.

## What you need
- **O1's conformance app:** `gotauth.plugins.oauth_provider.conformance:create_app`. It is a FastAPI app with the OAuth server and two confidential test clients, and it prints their ids and secrets at startup.
- **The test plan configuration** at `src/gotauth/plugins/oauth_provider/conformance/plan.json`, plan `oidcc-basic-certification-test-plan`. Its variants: discovery, static clients, `client_secret_basic`, `response_type=code`.
- **An https URL the suite can reach.**
  - For the hosted suite, this has to be a public URL, for example through a tunnel to the dev container.
  - For a local copy of the suite, the app must be reachable over https from the suite's containers.
- **The app's sign-in page.** The app creates one test user at startup (`CONFORMANCE_EMAIL` and `CONFORMANCE_PASSWORD`, defaults `conformance@example.com` and `conformance-password`) and serves a form at `/sign-in`. The `browser` block in `plan.json` fills it in, then clicks Allow on the consent page.

## Steps
1. **Start the app** in the dev container, with the public URL as `GOTAUTH_BASE_URL` and the suite's callback as `CONFORMANCE_REDIRECT`:
   ```sh
   ./dev.sh sh -c 'GOTAUTH_BASE_URL=https://<public host> \
     CONFORMANCE_REDIRECT=https://www.certification.openid.net/test/a/gotauth/callback \
     uv run uvicorn gotauth.plugins.oauth_provider.conformance:create_app --factory --host 0.0.0.0'
   ```
   For a local suite, use its callback (`https://localhost.emobix.co.uk:8443/test/a/gotauth/callback`) instead.
2. **Fill in `plan.json`.**
   - Copy the printed `client` and `client2` credentials into it.
   - Set `server.discoveryUrl` to `https://<public host>/api/auth/.well-known/openid-configuration`.
   - Replace `https://op.example.test` in the `browser` block's `match` values with `https://<public host>`. If you changed the test user, change its email and password there too.
3. **Create the test plan.**
   - **Hosted suite:** sign in at `https://www.certification.openid.net`, create a test plan, and paste the JSON.
   - **Local suite:** clone `https://gitlab.com/openid/conformance-suite`, then follow its README to build and start it with Docker Compose.
4. **Run every module in the plan,** then export the results.
5. **Record the run** in `O1-<date>.md`, using the template in [O1-2026-10-10.md](O1-2026-10-10.md). The date is the day of the run.

## When to run
- Before each release that changes `plugins/oauth_provider/`.
- When the suite publishes a new version of the plan.
