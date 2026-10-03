# G1: Landing page and waitlist

| | |
|---|---|
| Lane / wave | Growth / **Phase 0**, parallel with F1 |
| Size | S (1 agent-day) |
| Depends on | none |
| Can start | now (until F1's `dev.sh` exists, run Node with `docker run --rm -it -v "$PWD:/w" -w /w node:24 ...`) |
| Write scope | `apps/landing/**` |
| Allowed new deps | `astro` and official Astro integrations (e.g. sitemap) as devDependencies in `apps/landing/package.json`. No UI kits, analytics or tracking scripts |

## Goal
A fast, accessible static page on gotauth.dev that states the pitch and collects waitlist emails, so the Phase 0 demand test can run (>= 30 signups is one way to pass it).

## Build
- Astro, `output: "static"`, its own `package.json` with a pinned `packageManager` and its own `pnpm-lock.yaml`. All Node commands in Docker: `./dev.sh pnpm --dir apps/landing build`; dev server via `docker compose run --rm --service-ports dev pnpm --dir apps/landing dev --host 0.0.0.0`.
- Content from `docs/build-plan.md`, factual and plain:
  - Hero: "Got auth?" and the one-line pitch. Actions: "Join the waitlist", "Star on GitHub".
  - Why now: the four build-plan points, each linked to its source (fastapi-users maintenance notice, Amplifying benchmark, MCP SDK and FastMCP docs, JetBrains survey).
  - Code: three short snippets, highlighted at build time with Astro's built-in Shiki (no client JS), each labelled "planned API, may change". Copy the API from the `docs/build-plan.md` code block and CONTRACTS 13.2, never invent names:
    - FastAPI setup: `GotAuth(...)`, `app.include_router(auth.fastapi.router(), prefix="/api/auth")`, `CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]`.
    - FastMCP: `from gotauth.integrations.mcp import fastmcp_auth`, then `FastMCP(..., auth=fastmcp_auth(auth, resource="https://mcp.example.com/mcp", scopes=["projects:read"]))`.
    - API keys: `from gotauth.plugins.api_key import api_key`, `plugins=[api_key()]`, then `curl -H "x-api-key: gak_..."`.
  - Comparison: the build-plan "Why not X?" table, sourced, with a "last checked" date and a fair tone (R1 refines it later).
  - Waitlist, a short privacy note, footer (GitHub, MIT license, contact).
- Waitlist: a plain `<form method="post">` whose `action` is `import.meta.env.PUBLIC_WAITLIST_ENDPOINT`, a free form backend the owner picks. The README compares two options with free tiers and no tracking (check their current terms). Email field with label, hidden honeypot, works without JavaScript; optional small script submits with fetch and shows an inline result. If the variable is unset at build time, show "Waitlist opens soon" and the GitHub link instead of a broken form.
- Own visual identity, not a template look: no stock illustrations or gradient blobs. System fonts or self-hosted fonts (no Google Fonts requests), light and dark via `prefers-color-scheme`, `prefers-reduced-motion` respected, works from 320px wide.
- No cookies, no analytics, no third-party scripts. Meta description, Open Graph image (static PNG), favicon, `robots.txt`, sitemap.
- `apps/landing/README.md`: dev, build, env vars, deploy.
  - Cloudflare Pages: build `pnpm --dir apps/landing build`, output `apps/landing/dist`, set `PUBLIC_WAITLIST_ENDPOINT`, custom domain gotauth.dev.
  - GitHub Pages as the alternative: needs a workflow in `.github/`, so file `docs/requests/G1-pages-workflow.md` with the YAML instead of adding it.

## Acceptance tests
- `./dev.sh pnpm --dir apps/landing build` succeeds and emits only static files; the built HTML references no third-party origin except the form action.
- Lighthouse (DevTools or PageSpeed Insights on a preview deploy) >= 95 in Performance, Accessibility, Best Practices and SEO, mobile and desktop. Reports attached to the PR.
- Keyboard-only: every link and the form are reachable with a visible focus ring; inputs are labelled; form errors use `aria-live`; contrast meets WCAG AA in both themes.
- With JavaScript disabled, the form posts to the configured endpoint; a filled honeypot is rejected or ignored.
- Copy has no em dashes, emojis or marketing filler (grep in the PR).

## Out of scope
- Docs site and llms.txt (G2); launch posts (G5); comparison research (R1).

## Notes
- `.dev` is on the HSTS preload list: the site only works over HTTPS. Both hosts issue certificates.
- Use the current stable Astro release and check its docs for env variables and static output; record the version in the README.
