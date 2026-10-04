# D2: UI components (shadcn registry) and typed fetch client

| | |
|---|---|
| Lane / wave | UI / **Wave 1** (part 1) and **Wave 3** (part 2, plugin components) |
| Size | M (2 agent-days) |
| Depends on | Part 1: M0 HTTP models (`contracts/http_models.py`). Part 2: P1, P2, P3, P5 and O1 merged |
| Can start | Part 1 (core components, client for CONTRACTS 13.1) after M0; part 2 (plugin components) once those plugins merge |
| Write scope | `registry/**` |
| Allowed new deps | devDependencies in `registry/package.json`: shadcn (CLI), react, react-dom, typescript, tailwindcss, vitest, jsdom, @testing-library/react, @testing-library/user-event, msw, axe-core, plus next and vite for the fixtures. Component runtime deps: only what the shadcn primitives they use need |

## Goal
Copy-in React components and a typed client that talk to GotAuth's HTTP API with cookies, installable with the shadcn CLI into Next.js App Router and Vite React apps. G4's example and the hero clip use them.

## Build
- `registry/registry.json` (shadcn registry schema) with items: SignInForm, SignUpForm, SocialButtons, UserButton, SessionList, TwoFactorSetup, TwoFactorChallenge, PasskeyButton, ApiKeyManager, OrgSwitcher, ConsentScreen, plus `lib/gotauth-client.ts`, `lib/webauthn.ts` and `hooks/use-session.ts`. shadcn primitives (button, input, label, card, dropdown-menu, avatar, dialog, table, alert, input-otp) as `registryDependencies`. `pnpm --dir registry build` runs `shadcn build` into `registry/public/r/`.
- `lib/gotauth-client.ts`: `createGotAuthClient({ baseURL = "/api/auth", fetch })`.
  - One method per endpoint id in camelCase (`signUpEmail` ... `unlinkAccount` for 13.1); JSON fields stay snake_case. Request bodies follow the C2, C3 and C4 briefs.
  - Transport per CONTRACTS 5 and 10.1: GET inputs go in the query; POST, PATCH and DELETE send a JSON body with `Content-Type: application/json` on every call (the server answers 415 UNSUPPORTED_MEDIA_TYPE otherwise), including `deleteUser` (DELETE `/user` with `{password?}`). Every call uses `credentials: "include"`. Returns `{ data, error }`; `error` = `{ code, message, status }` parsed from `ErrorOut`; network failures -> `code: "NETWORK_ERROR"`.
  - Plugin namespaces, methods named after the verb-first endpoint ids; paths and bodies from each brief (the briefs win on any difference):
    - `apiKeys` (P1, CONTRACTS 12.3): `createApiKey`, `listApiKeys`, `updateApiKey`, `deleteApiKey` (`/api-keys`, `/api-keys/{id}`).
    - `twoFactor` (P2): `enableTwoFactor`, `verifyTotp`, `verifyBackupCode`, `disableTwoFactor`, `regenerateBackupCodes`, `sendTwoFactorOtp`, `verifyTwoFactorOtp`.
    - `passkey` (P3): `getPasskeyRegistrationOptions`, `verifyPasskeyRegistration`, `getPasskeySignInOptions`, `signInPasskey`, `listPasskeys`, `renamePasskey`, `deletePasskey`.
    - `magicLink` / `emailOtp` (P4): `sendMagicLink`, `sendEmailOtp`, `verifyEmailOtp` (`verify_magic_link` is the emailed GET link; the client never calls it).
    - `organization` (P5): `listOrganizations`, `createOrganization`, `setActiveOrganization`, `hasPermission`.
    - `oauth2` (O1): `oauthAuthorize` in JSON mode (`Accept: application/json`, per O1) -> `{consent_id, client, scopes, resource, redirect_host, loopback_only}` or `{url}`.
  - Anything not in a brief: path from CONTRACTS section 5 plus `// TODO(<WP>)`.
  - TypeScript types mirror `contracts/http_models.py` (incl. `SessionWithUserOut`, `ChallengeOut`, `ErrorOut`); preferably generated from the models' JSON Schema by a script run in Docker, otherwise hand-written with a test against sample payloads.
- `hooks/use-session.ts`: `useSession()` -> `{ data: SessionWithUserOut | null, error, isPending, refetch }` over `GET /session` (`getSession`), one shared store (`useSyncExternalStore`), refetched after sign-in, sign-out and revoke.
- `lib/webauthn.ts`: base64url <-> ArrayBuffer for creation and request options and credential responses; use `PublicKeyCredential.parseCreationOptionsFromJSON` / `toJSON` when the browser has them, manual conversion otherwise.
- Components, all `"use client"`, `GotAuthProvider` supplies the client:
  - SignInForm: email + password, renders SocialButtons, handles ChallengeOut (`onChallenge` or inline TwoFactorChallenge). SignUpForm: shows the same "check your email" message for StatusOut. SocialButtons: `signInSocial`, then `window.location.assign(url)`.
  - UserButton (avatar, sign out), SessionList (current marked via `current_session_id`, revoke, revoke others), TwoFactorSetup (QR from `totp_uri` rendered locally, backup codes shown once), PasskeyButton (`getPasskeySignInOptions` -> `navigator.credentials.get` -> `signInPasskey`), ApiKeyManager (raw key shown once with copy, then dropped from state), OrgSwitcher.
  - ConsentScreen (client name, CIMD host, the redirect host from `redirect_host`, a warning when `loopback_only` is true, scopes, approve or deny; MCP authorization 2026-07-28 requires the redirect host on screen): `oauth_consent` takes a form body (12.3), so it submits a native `<form method="post">` to `/oauth2/consent` and the browser follows the redirect to the client.
- Rules: tokens never in localStorage or sessionStorage; no `dangerouslySetInnerHTML`; labelled inputs, `autocomplete` (`email`, `current-password`, `new-password`, `one-time-code`), errors in an `aria-live` region, full keyboard use.
- Fixtures `registry/fixtures/next-app` (App Router) and `registry/fixtures/vite-react` install the built items and must type-check and build.
- **Contract check against the real backend (part 2):**
  - `registry/scripts/export_openapi.py` (Python, runs in the dev container) builds a FastAPI app with every merged plugin and writes `registry/openapi.json`.
  - CI regenerates the types with openapi-typescript and fails if the typed client disagrees.
  - Drift between the UI and the backend therefore shows up as a failing check, not a runtime bug.

## Acceptance tests
- `./dev.sh pnpm --dir registry test` (Vitest + Testing Library + MSW) covers every component and client method, including error parsing and ChallengeOut handling.
- Client sends `credentials: "include"` on every call and `Content-Type: application/json` on every POST, PATCH and DELETE (MSW assertions); no storage API is touched.
- `deleteUser` sends DELETE with a JSON body; `useSession` types `data` as `SessionWithUserOut | null`.
- ApiKeyManager: the raw key appears once and is gone after closing the dialog.
- ConsentScreen renders a form posting form-encoded fields, with no fetch call.
- ConsentScreen shows `redirect_host`, and shows the loopback-only warning when `loopback_only` is true and never otherwise.
- webauthn helpers round-trip random byte arrays.
- `pnpm --dir registry build` produces `public/r/*.json`; both fixtures pass `tsc --noEmit` and build.
- axe check in jsdom on each component: no violations.

## Out of scope
- Server endpoints (C2-C4, P1-P5, O1); the npm `gotauth` package (later); the example app (G4).

## Notes
- Check the current shadcn registry docs (`registry.json` schema, `shadcn build`) and record the CLI version; React 19 and current Next.js and Vite majors.
- If an endpoint shape differs from its brief once merged, the merged code wins; update the client.
