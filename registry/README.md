# UI registry

Copy-in React components and a typed fetch client for GotAuth's HTTP API, published as a [shadcn registry](https://ui.shadcn.com/docs/registry) so apps install them with the shadcn CLI. Work package D2 owns this folder.

## Format

- `registry.json`: the shadcn registry file listing every item (components, `lib/gotauth-client.ts`, `lib/webauthn.ts`, `hooks/use-session.ts`).
- Item sources next to it; `pnpm --dir registry build` runs `shadcn build` into `public/r/`.
- `fixtures/next-app` and `fixtures/vite-react` install the built items and must type-check and build.
- This is a standalone pnpm project with its own `pnpm-lock.yaml`. There is no root pnpm workspace. `package.json` pins `"packageManager": "pnpm@12.8.1"`, the version in the dev image.

## Commands

Run in the dev container:

```bash
./dev.sh pnpm --dir registry install --frozen-lockfile
./dev.sh pnpm --dir registry test
./dev.sh pnpm --dir registry build
```
