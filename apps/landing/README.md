# gotauth.dev landing page

The static landing page and waitlist for [gotauth.dev](https://gotauth.dev): the pitch, the "Why now" evidence, three planned-API code snippets, the "Why not X?" comparison and a waitlist form. Work package G1.

- No cookies, no analytics, no third-party scripts, styles or fonts. The only third-party request is the waitlist form posting to the form service you configure.
- Works without JavaScript. A small inline script improves the form (inline errors and a success message without leaving the page).
- Light and dark themes follow the system setting. Motion is off when reduced motion is requested. Works from 320px wide.

## Versions

Checked on 2026-10-03.

| Tool | Version | Where it is pinned |
|---|---|---|
| Astro | 7.3.5 | `package.json` (exact), `pnpm-lock.yaml` |
| @astrojs/sitemap | 3.7.4 | `package.json` (exact), `pnpm-lock.yaml` |
| pnpm | 12.8.1 | `packageManager` in `package.json` (the dev image pins the same) |
| Node | 24 | `engines` in `package.json`, `.node-version` (for Cloudflare Pages) |

This is a standalone pnpm project with its own lockfile (there is no root workspace). `pnpm-workspace.yaml` exists only to hold `allowBuilds` (esbuild's install script), which pnpm 12 reads from that file.

## Files

| Path | What it holds |
|---|---|
| `src/pages/index.astro` | All page copy: hero, "Why now" with sources, snippet intros, comparison table |
| `src/snippets/*` | The code shown on the page, copied from `docs/build-plan.md` |
| `src/components/Waitlist.astro` | The form, the "Waitlist opens soon" fallback and the form script |
| `src/lib/site.ts` | Reads the environment variables; `LAST_CHECKED` date for the evidence |
| `src/lib/code.ts` | Code highlighting theme (see "Code highlighting" below) |
| `src/styles/global.css` | All styles and the color tokens for both themes |
| `src/pages/thanks.astro` | `/thanks/`, for form services that redirect after a post |
| `public/` | Favicon, Open Graph image, `robots.txt`, Cloudflare `_headers` |
| `design/` | SVG sources of `og.png` and `apple-touch-icon.png` |
| `scripts/check-dist.mjs` | Acceptance checks on the built site |
| `scripts/check-contrast.mjs` | WCAG contrast checks for every color pair, both themes |
| `scripts/mock-waitlist.mjs` | A local stand-in form service for testing the form |

## Run it

Every command runs in the dev container through `./dev.sh` (PowerShell: `.\dev.ps1`) from the repo root. The container has Node 24 and pnpm 12.8.1, and keeps pnpm's store in the shared `gotauth-pnpm-store` volume.

```bash
./dev.sh pnpm --dir apps/landing install --frozen-lockfile
./dev.sh pnpm --dir apps/landing build    # writes apps/landing/dist
./dev.sh pnpm --dir apps/landing check    # build, then the contrast and dist checks (CI runs this)
```

Dev server or a preview of the built site, on http://localhost:4321 (`--ports` publishes the container's ports on 127.0.0.1 only):

```bash
./dev.sh --ports pnpm --dir apps/landing dev --host 0.0.0.0
./dev.sh --ports pnpm --dir apps/landing preview --host 0.0.0.0    # after a build
```

`pnpm check` needs the whole repository, not only this folder: the snippet check compares `src/snippets/` with `docs/build-plan.md`.

## Environment variables

All are optional and read at build time (Astro inlines `PUBLIC_` variables into the static HTML). For local builds, copy `.env.example` to `.env`; on a host, set them in the project settings and rebuild after a change.

| Variable | Default | Effect |
|---|---|---|
| `PUBLIC_WAITLIST_ENDPOINT` | unset | The form's `action` URL; must be `https`. Unset: the page shows "Waitlist opens soon" and the GitHub link instead of a form |
| `PUBLIC_WAITLIST_HONEYPOT` | `_gotcha` | Name of the hidden honeypot field the form service checks |
| `PUBLIC_WAITLIST_FIELDS` | unset | Extra hidden fields, URL-encoded: `access_key=...&subject=...` |
| `PUBLIC_WAITLIST_PROVIDER` | unset | The service name shown in the privacy note, e.g. `Formspree` |
| `PUBLIC_GITHUB_URL` | `https://github.com/gotauth/gotauth` | "Star on GitHub", nav and footer links; the license link is `<url>/blob/main/LICENSE` |
| `PUBLIC_CONTACT_EMAIL` | unset | Footer and privacy-note contact. Unset: the footer links to GitHub issues |

The build fails on an invalid endpoint (not a URL, or not `https`), so a typo never ships a broken form. The endpoint's origin is added to the page's Content-Security-Policy (`form-action` and `connect-src`), so the form can post nowhere else.

## Waitlist: pick a form service

The form is a plain `<form method="post">` with an `email` field and a hidden honeypot, so any form service that accepts a URL-encoded or multipart POST works. Two with free tiers, checked on 2026-10-03 (check their current terms and privacy policy before you choose):

| | Formspree | Web3Forms |
|---|---|---|
| Free tier | 50 submissions a month, 30-day submission archive | 250 submissions a month (per third-party summaries; their site blocked automated checks, so confirm on web3forms.com) |
| Where signups go | Dashboard (30-day archive on free) and email | Email to the address tied to the access key |
| Endpoint | `https://formspree.io/f/<form-id>` | `https://api.web3forms.com/submit` |
| Extra fields | none | `access_key=<key>` (a public key, meant to be in the HTML) |
| Honeypot | `_gotcha` (filled: silently ignored) | `botcheck` (still supported; their docs now prefer hCaptcha) |
| With JavaScript | JSON response, inline success message | JSON response, inline success message |
| Without JavaScript | Formspree's own confirmation page; a custom redirect needs a paid plan | Can redirect to `https://gotauth.dev/thanks/` with a `redirect` field |
| Tracking | Non-JS posts go through a Google reCAPTCHA page by default. Turn reCAPTCHA off in the form's Settings, under "Spam protection" (allowed on every plan) | No CAPTCHA unless you add one |

On Formspree's free plan the archive keeps 30 days, so keep the notification emails (or export the list) to keep older signups. Neither service needs a script or cookie on gotauth.dev.

Formspree:

```bash
PUBLIC_WAITLIST_ENDPOINT=https://formspree.io/f/<form-id>
PUBLIC_WAITLIST_PROVIDER=Formspree
```

Web3Forms:

```bash
PUBLIC_WAITLIST_ENDPOINT=https://api.web3forms.com/submit
PUBLIC_WAITLIST_HONEYPOT=botcheck
PUBLIC_WAITLIST_FIELDS=access_key=<key>&subject=GotAuth%20waitlist&redirect=https%3A%2F%2Fgotauth.dev%2Fthanks%2F
PUBLIC_WAITLIST_PROVIDER=Web3Forms
```

### Test the form locally

`scripts/mock-waitlist.mjs` behaves like Formspree (JSON for `fetch`, a redirect for plain posts, a filled honeypot is ignored) and prints one JSON line per post. It listens on port 8000, one of the ports `--ports` publishes:

```bash
./dev.sh --ports sh -c "cd apps/landing \
  && PUBLIC_WAITLIST_ENDPOINT=http://localhost:8000/submit PUBLIC_WAITLIST_PROVIDER='a local mock' pnpm build \
  && (PORT=8000 THANKS_URL=http://localhost:4321/thanks/ node scripts/mock-waitlist.mjs &) \
  && pnpm preview --host 0.0.0.0"
```

(`http://localhost` endpoints are accepted only for this kind of local test.) Then open http://localhost:4321/#waitlist and try: a valid address, an empty or malformed one, the same with JavaScript disabled, and a filled honeypot (set it in DevTools). With the mock stopped, the form shows the "could not be reached" error and keeps the typed address.

## Deploy

`.dev` domains are on the HSTS preload list, so gotauth.dev only works over HTTPS. Both hosts below issue certificates for custom domains.

### Cloudflare Pages (recommended)

1. Cloudflare dashboard -> Workers & Pages -> Create -> Pages -> connect the `gotauth/gotauth` repository.
2. Build settings:
   - Production branch: `main`
   - Framework preset: Astro (or None)
   - Root directory (advanced): `apps/landing`
   - Build command: `pnpm build`
   - Build output directory: `dist`
3. Environment variables (Production, and Preview if previews should have a working form): `PUBLIC_WAITLIST_ENDPOINT` and the other `PUBLIC_` variables from the table above. Add `PNPM_VERSION=12.8.1` too; Cloudflare's v3 build image ships pnpm 10.11 and Node 22.16 by default. Node 24 comes from `.node-version`.
4. Save and deploy. Every pull request then gets a preview URL, which is where to run Lighthouse.
5. Custom domains -> Set up a custom domain -> `gotauth.dev`. With the domain's DNS on Cloudflare the record is added for you; otherwise add the CNAME it shows. Add `www.gotauth.dev` as well if you want it, and redirect it to the apex with a Redirect Rule.

The brief's repo-root form of the same settings also works: root directory empty, build command `pnpm --dir apps/landing install --frozen-lockfile && pnpm --dir apps/landing build`, output directory `apps/landing/dist`, plus `NODE_VERSION=24` and `PNPM_VERSION=12.8.1`. Neither form has been tried on Cloudflare yet; check the first deploy's build log for the Node and pnpm versions.

`public/_headers` sets security headers on Cloudflare (`X-Frame-Options: DENY`, `nosniff`, a strict referrer policy, a locked-down `Permissions-Policy`) and long cache lifetimes for hashed assets. The Content-Security-Policy itself is a `<meta>` tag in every page, so it works on any host.

### GitHub Pages (alternative)

This needs a workflow under `.github/`, outside G1's write scope, so it is filed as a request: [`docs/requests/G1-pages-workflow.md`](../../docs/requests/G1-pages-workflow.md) has the YAML and the settings. GitHub Pages ignores `_headers`, so the framing and permissions headers above are not sent there; the CSP `<meta>` tag still applies.

## Lighthouse

The brief asks for >= 95 in Performance, Accessibility, Best Practices and SEO, mobile and desktop, with the reports attached to the PR.

Measured locally on 2026-10-04 with Lighthouse 13.5.0 and headless Chromium 154, against `astro preview` in Docker. The same scores came from a build with a mock form endpoint and from the final build without one ("Waitlist opens soon"):

| | Performance | Accessibility | Best Practices | SEO |
|---|---|---|---|---|
| Mobile | 100 | 100 | 100 | 100 |
| Desktop | 100 | 100 | 100 | 100 |

Mobile LCP 0.8 to 1.3 s, desktop LCP 0.2 to 0.3 s, TBT 0 to 20 ms, CLS 0. The home page is 34 KB of HTML (about 9.5 KB gzipped) with CSS and the form script inline, and no other requests except the favicon.

Repeat it on the Cloudflare preview URL of the PR (the real host, with HTTPS, compression and headers):

- Chrome DevTools -> Lighthouse -> Mode: Navigation; Device: Mobile, then Desktop; all four categories -> Analyze. Save each report as HTML (menu -> Save as HTML) and attach it to the PR.
- Or [PageSpeed Insights](https://pagespeed.web.dev/) with the preview URL; it reports mobile and desktop.
- Or the CLI in Docker, the way the scores above were measured:

  ```bash
  docker run --rm -v "$PWD:/out" -w /out node:24 sh -c "apt-get update && apt-get install -y chromium \
    && CHROME_PATH=/usr/bin/chromium npx -y lighthouse@13.5.0 https://<preview>.pages.dev/ \
       --chrome-flags='--headless=new --no-sandbox' --output html --output-path ./lighthouse-mobile.html"
  ```

  Add `--preset=desktop` for the desktop run.

## Accessibility

Built for WCAG 2.1 AA and checked with the keyboard, the browser's accessibility tree and `scripts/check-contrast.mjs`:

- Landmarks (`header`, `nav`, `main`, `footer`), a skip link, one `h1` and a sequential heading outline.
- Every focusable element shows a 3px focus ring with at least 3:1 contrast in both themes; Tab order follows the page. Buttons, the email field and the header and footer links are at least 44px tall; links inside sentences are exempt under WCAG 2.5.8.
- The email field has a visible label and a hint above it. Errors appear only after the person leaves the field or submits, sit right under the field, are announced through an `aria-live` region, set `aria-invalid`, and use an icon and a thicker border as well as color. Results of a submit go to a `role="status"` region.
- The comparison table has a caption and row and column headers. Below 48rem it restacks as one card per alternative instead of scrolling sideways, with explicit table roles so screen readers still get a table.
- Code blocks scroll on their own and are keyboard focusable.
- All text and UI color pairs meet AA in light and dark; `pnpm check` fails if a token change breaks one.
- Smooth scrolling and transitions only run when `prefers-reduced-motion` is not set. Nothing animates on its own.

Not yet done: a pass with a real screen reader (NVDA or VoiceOver).

## Code highlighting

Snippets are highlighted at build time by Astro's `<Code />` (Shiki), so no highlighting script ships. Shiki normally writes colors into inline `style` attributes, which a strict CSP blocks and which cannot follow the light and dark tokens. `src/lib/code.ts` gives Shiki a theme of placeholder colors and a transformer that replaces each one with a class (`tk-keyword`, `tk-string`, ...); `global.css` colors those classes. The code panel stays dark in both themes.

## Updating the content

- **Evidence and comparison:** edit `reasons` and `alternatives` in `src/pages/index.astro`, then update `LAST_CHECKED` in `src/lib/site.ts`. Every claim links to its source; keep it that way. The facts follow `docs/build-plan.md` as updated by R1; `docs/launch/comparison.md` has the full, sourced comparison.
- **Snippets:** edit `src/snippets/*`. They must follow `docs/build-plan.md` and CONTRACTS 13.2; `pnpm check` fails if the key API lines drift from the plan. Every snippet keeps the "Planned API, may change" label until the API ships.
- **Open Graph image and icons:** edit `design/og.svg` or `design/icon.svg`, then render them (DejaVu fonts, so the result is the same on any machine):

  ```bash
  MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/apps/landing:/w" -w /w node:24 sh -c "apt-get update \
    && apt-get install -y --no-install-recommends librsvg2-bin fonts-dejavu-core \
    && rsvg-convert -w 1200 -h 630 design/og.svg -o public/og.png \
    && rsvg-convert -w 180 -h 180 design/icon.svg -o public/apple-touch-icon.png \
    && rsvg-convert -w 32 -h 32 public/favicon.svg -o public/favicon-32.png"
  ```

- **Copy style:** no emojis, no em or en dashes, no marketing filler. `pnpm check` scans the built pages and the sources for all three, and the repository's `scripts/check_text.py` checks dashes and emoji everywhere.
