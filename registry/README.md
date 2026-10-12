# UI registry

Copy-in React components and a typed fetch client for GotAuth's HTTP API, published as a
[shadcn registry](https://ui.shadcn.com/docs/registry) so apps install them with the
shadcn CLI. Work package D2 owns this folder. Built against React 19.3, Next.js 16,
Vite 8, Tailwind CSS 4.3 and shadcn CLI 4.21 (checked 2026-10-07).

## Install in an app

Add the registry to the app's `components.json`, then add items by name:

```json
{ "registries": { "@gotauth": "https://gotauth.dev/r/{name}.json" } }
```

```bash
npx shadcn@latest add @gotauth/sign-in-form @gotauth/user-button @gotauth/use-session
```

Wrap the app in `<GotAuthProvider baseURL="/api/auth">` and use the components inside it.

## Items (part 1)

| Item | What it is |
|---|---|
| `gotauth-client` | `createGotAuthClient({ baseURL, fetch })`: one method per endpoint, `{ data, error }` results |
| `gotauth-provider` | `GotAuthProvider` and `useGotAuthClient()` |
| `use-session` | `useSession()`: `{ data: SessionWithUserOut \| null, error, isPending, refetch }`, shared, refetched after sign-in and sign-out |
| `webauthn` | base64url and ArrayBuffer helpers for passkeys |
| `sign-in-form`, `sign-up-form`, `social-buttons` | Email and password forms with social buttons |
| `user-button` | Avatar with a sign-out menu |
| `session-list` | Signed-in devices, sign out one or all others |
| `api-key-manager` | Create, list and delete API keys; a new key is shown once |

Part 2 (two-factor, passkeys, organizations, OAuth consent and the OpenAPI drift check)
follows once those plugins are built.

## Client rules

- Every call sends `credentials: "include"`, so the session cookie does the work. Tokens
  are never put in `localStorage` or `sessionStorage`.
- POST, PATCH and DELETE always send a JSON body with `Content-Type: application/json`
  (GotAuth answers 415 otherwise); GET inputs go in the query string.
- Errors come back as `{ code, message, status }` from GotAuth's error body; network
  failures are `NETWORK_ERROR`.

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
