# UI registry

Copy-in React components and a typed fetch client for GotAuth's HTTP API, published as a
[shadcn registry](https://ui.shadcn.com/docs/registry) so apps install them with the
shadcn CLI. Work package D2 owns this folder. Built against React 19.3, Next.js 16,
Vite 8, Tailwind CSS 4.3 and shadcn CLI 4.21 (checked 2026-10-07).

## Install in an app

Add the registry to the app's `components.json`, then add items by name:

```json
{ "registries": { "@gotauth": "https://gotauth.ablacky.com/r/{name}.json" } }
```

```bash
npx shadcn@latest add @gotauth/sign-in-form @gotauth/user-button @gotauth/use-session
```

Wrap the app in `<GotAuthProvider baseURL="/api/auth">` and use the components inside it.

## Items

| Item | What it is |
|---|---|
| `gotauth-client` | `createGotAuthClient({ baseURL, fetch })`: one method per endpoint, `{ data, error }` results |
| `gotauth-provider` | `GotAuthProvider` and `useGotAuthClient()` |
| `use-session` | `useSession()`: `{ data: SessionWithUserOut \| null, error, isPending, isRefetching, refetch }`, shared, refetched after sign-in and sign-out. `isPending` is true only until the first answer; refetches keep the last one and set `isRefetching`, so pages that wait for `isPending` keep their forms mounted |
| `webauthn` | base64url and ArrayBuffer helpers for passkeys |
| `sign-in-form`, `sign-up-form`, `social-buttons` | Email and password forms with social buttons; the sign-in form shows the two-factor step itself unless you pass `onChallenge` |
| `user-button` | Avatar with a sign-out menu |
| `session-list` | Signed-in devices, sign out one or all others |
| `api-key-manager` | Create, list and delete API keys; a new key is shown once |
| `two-factor-setup` | Turn on an authenticator app (QR code, then a code to confirm, then backup codes shown once), get new backup codes, or turn it off. With `duringSignIn` it is the enforced setup step of a sign-in |
| `two-factor-challenge` | The second sign-in step: authenticator code, backup code or emailed code, with "don't ask again on this device" |
| `qr-code` | A QR code drawn in the page as SVG (with [uqr](https://github.com/unjs/uqr) 0.1.3), so the TOTP secret never leaves the browser |
| `passkey-button` | `mode="sign-in"` (no email needed) or `mode="register"` (add a passkey to the account) |
| `org-switcher` | Choose the organization the session acts in, or the personal account |
| `consent-screen` | The OAuth consent screen: app name, where the browser goes next (`redirect_host`), a warning for local-only apps, scopes; Allow and Deny post a native form |
| `connected-apps` | Apps with OAuth access (for example MCP clients), each with a Revoke button |

**Plugin namespaces of the client:** `apiKeys`, `twoFactor`, `passkey`, `magicLink`,
`emailOtp`, `organization` and `oauth2`. Admin and agent endpoints are not in the client
yet.

**An OAuth consent page** of your own: set `oauth_provider(consent_page="/consent")`.
GotAuth sends the browser there with `?consent_id=...`; the page calls
`client.oauth2.getOauthConsent({ consent_id })` and renders `ConsentScreen` with the
result. Allow and Deny post the form to GotAuth, which redirects back to the app.
Serve that page with `Content-Security-Policy: frame-ancestors 'none'`, as GotAuth's
built-in consent page does, so no other site can frame it and trick a click on Allow.

## Client rules

- Every call sends `credentials: "include"`, so the session cookie does the work. Tokens
  are never put in `localStorage` or `sessionStorage`.
- POST, PATCH and DELETE always send a JSON body with `Content-Type: application/json`
  (GotAuth answers 415 otherwise); GET inputs go in the query string.
- Errors come back as `{ code, message, status }` from GotAuth's error body; network
  failures are `NETWORK_ERROR`.

## Contract check against the backend

`openapi.json` is the HTTP API of GotAuth with every plugin, written by
`scripts/export_openapi.py`. `pnpm typecheck` turns its schemas into TypeScript types
(`scripts/openapi-types.mjs`, into the ignored `tests/generated/`) and `tests/contract.ts`
checks that the client's request and response types match them field by field. On the
Python side, `tests/registry/test_openapi.py` fails when `openapi.json` is out of date.
A change on either side therefore fails a check instead of breaking at runtime. After
changing an endpoint:

```bash
./dev.sh uv run python registry/scripts/export_openapi.py
./dev.sh pnpm --dir registry run typecheck
```

## Layout

- `registry.json`: the shadcn registry; `pnpm build` runs `shadcn build` into `public/r/`.
- `src/`: item sources. `src/components/ui/` and `src/lib/utils.ts` are the shadcn
  primitives the items depend on (added with `shadcn add`), used by tests and fixtures.
- `tests/`: Vitest, Testing Library, MSW and axe-core.
- `fixtures/next-app`, `fixtures/vite-react`: `scripts/install-fixtures.mjs` installs the
  built items into them, then both must type-check and build.

## Commands

Run in the dev container:

```bash
./dev.sh pnpm --dir registry install --frozen-lockfile
./dev.sh pnpm --dir registry run check      # typecheck, tests, build, fixtures
./dev.sh pnpm --dir registry test
./dev.sh pnpm --dir registry build
```

## npm package `@gotauth/client`

`registry/npm/` publishes the typed fetch client (`src/lib/gotauth-client.ts`, the same file the registry items use) as the npm package `@gotauth/client`. (npm refuses the unscoped name `gotauth` as too similar to `oauth`.) `pnpm build:npm` compiles it to `npm/dist/`, copies the root `LICENSE` and imports the result once as a smoke test; `pnpm check` runs it too.

To release: set `version` in `npm/package.json`, merge, then push a tag `js-v<version>`. `.github/workflows/npm-release.yml` publishes it with provenance.
