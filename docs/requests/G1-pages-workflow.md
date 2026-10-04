# G1 request: GitHub Pages workflow for the landing page

**From:** G1 (landing page). **Needs:** a new file `.github/workflows/landing-pages.yml`, outside G1's write scope (`apps/landing/**`).

## What

A workflow that builds `apps/landing` and deploys it to GitHub Pages on every push to `main` that touches it. It is the alternative to Cloudflare Pages named in the G1 brief; Cloudflare Pages needs no repository file (see `apps/landing/README.md`, "Deploy").

## Why

The G1 brief asks for GitHub Pages as a documented alternative host. Deploying there needs a workflow under `.github/`, which G1 may not add.

Only add it if the owner picks GitHub Pages over Cloudflare Pages. Running both against the same custom domain does not work.

## Proposed file

Actions are pinned by commit SHA (tags checked on 2026-10-04). `withastro/action` reads the pnpm version from `apps/landing/package.json` (`packageManager`), installs, builds and uploads the Pages artifact; the `build-cmd` also runs the G1 checks, so a failing check stops the deploy.

```yaml
# .github/workflows/landing-pages.yml
name: Landing page (GitHub Pages)

on:
  push:
    branches: [main]
    paths:
      - "apps/landing/**"
      - ".github/workflows/landing-pages.yml"
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: withastro/action@3eafd002e65cc31b4f0eae0bb05450d521562247 # v6.1.3
        with:
          path: apps/landing
          node-version: 24
          build-cmd: pnpm run build && pnpm run check
        env:
          PUBLIC_WAITLIST_ENDPOINT: ${{ vars.PUBLIC_WAITLIST_ENDPOINT }}
          PUBLIC_WAITLIST_HONEYPOT: ${{ vars.PUBLIC_WAITLIST_HONEYPOT }}
          PUBLIC_WAITLIST_FIELDS: ${{ vars.PUBLIC_WAITLIST_FIELDS }}
          PUBLIC_WAITLIST_PROVIDER: ${{ vars.PUBLIC_WAITLIST_PROVIDER }}
          PUBLIC_GITHUB_URL: ${{ vars.PUBLIC_GITHUB_URL }}
          PUBLIC_CONTACT_EMAIL: ${{ vars.PUBLIC_CONTACT_EMAIL }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346 # v5.0.1
```

## Owner setup after merge

1. Repository Settings -> Pages -> Build and deployment -> Source: **GitHub Actions**.
2. Settings -> Secrets and variables -> Actions -> **Variables**: add the `PUBLIC_` variables from `apps/landing/README.md` (they end up in public HTML, so variables, not secrets).
3. Settings -> Pages -> Custom domain: `gotauth.dev`, then **Enforce HTTPS** once the certificate is issued. At the DNS provider, point the apex at GitHub Pages (the A and AAAA records GitHub lists) and verify the domain for the organization. A `CNAME` file is not needed when deploying with Actions.
4. Run the workflow once (Actions -> Landing page (GitHub Pages) -> Run workflow).

## Differences from Cloudflare Pages

- GitHub Pages ignores `apps/landing/public/_headers`, so `X-Frame-Options`, `Permissions-Policy` and the long cache lifetime for `/_astro/*` are not sent. The Content-Security-Policy still applies: it is a `<meta>` tag in every page.
- No preview deploys for pull requests, so Lighthouse runs against a local preview or production instead.
