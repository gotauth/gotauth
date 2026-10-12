# gotauth.ablacky.com landing page

The static landing page and waitlist for [gotauth.ablacky.com](https://gotauth.ablacky.com): the pitch, the "Why now" evidence, three planned-API code snippets, the "Why not X?" comparison and a waitlist form. Work package G1.

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
| Node | 24 | `engines` in `package.json`, `.node-version` (for hosts that read it) |

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
| `public/` | Favicon, Open Graph image, `robots.txt`, `.htaccess` (Apache headers, HTTPS, 404) |
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
| `PUBLIC_CONTACT_EMAIL` | unset | Footer contact, and where the privacy note sends removal requests. Unset: both point to GitHub issues, which are public, and the build prints a warning when the waitlist is on. Set it before the waitlist goes live |

The build fails on an invalid endpoint (not a URL, or not `https`), so a typo never ships a broken form. The endpoint's origin is added to the page's Content-Security-Policy (`form-action` and `connect-src`), so the form can post nowhere else.

## Waitlist: pick a form service

The form is a plain `<form method="post">` with an `email` field and a hidden honeypot, so any form service that accepts a URL-encoded or multipart POST works. Two with free tiers, checked on 2026-10-03 (check their current terms and privacy policy before you choose):

| | Formspree | Web3Forms |
|---|---|---|
| Free tier | 50 submissions a month, 30-day submission archive | 250 submissions a month (per third-party summaries; their site blocked automated checks, so confirm on web3forms.com) |
| Where signups go | Dashboard (30-day archive on free) and email | Email to the address tied to the access key. Their FAQ says submissions are not stored; their data processing agreement (web3forms.com/dpa, which blocked automated reads, so this is from search summaries) describes a 30-day dashboard history on free and up to 3 years of storage. Read the DPA before choosing |
| Endpoint | `https://formspree.io/f/<form-id>` | `https://api.web3forms.com/submit` |
| Extra fields | none | `access_key=<key>` (a public key, meant to be in the HTML) |
| Honeypot | `_gotcha` (filled: silently ignored) | `botcheck` (still supported; their docs now prefer hCaptcha) |
| With JavaScript | JSON response, inline success message | JSON response, inline success message |
| Without JavaScript | Formspree's own confirmation page; a custom redirect needs a paid plan | Can redirect to `https://gotauth.ablacky.com/thanks/` with a `redirect` field |
| Tracking | Non-JS posts go through a Google reCAPTCHA page by default. Turn reCAPTCHA off in the form's Settings, under "Spam protection" (allowed on every plan) | No CAPTCHA unless you add one |

On Formspree's free plan the archive keeps 30 days, so keep the notification emails (or export the list) to keep older signups. Neither service needs a script or cookie on gotauth.ablacky.com.

### Removing someone from the list

The privacy note promises removal on request: by email to `PUBLIC_CONTACT_EMAIL` (from the address that signed up, so you can match it), or through a GitHub issue when no contact address is set. When a request comes in:

1. **Match the address.** Use the sender of the email. For a GitHub issue, ask for a private way to confirm the address rather than having it posted in public.
2. **Delete it at the form service.**
   - **Formspree:** in the dashboard, open the form's submissions, search for the address, select the submission and delete it. If an older submission is no longer in the dashboard (30-day archive on free), there is nothing left to delete there.
   - **Web3Forms:** if the submission shows in the dashboard history, delete it there. If it does not, or you cannot delete it, ask Web3Forms support to delete the data for that address, since their data processing agreement describes storage beyond the dashboard window.
3. **Delete your own copies:** the notification email, any export or spreadsheet, and any mailing tool you imported the list into.
4. **Reply** that the address has been removed.

Check both services' current dashboards: these steps were written from their docs on 2026-10-04, not from a live account.

Formspree:

```bash
PUBLIC_WAITLIST_ENDPOINT=https://formspree.io/f/<form-id>
PUBLIC_WAITLIST_PROVIDER=Formspree
```

Web3Forms:

```bash
PUBLIC_WAITLIST_ENDPOINT=https://api.web3forms.com/submit
PUBLIC_WAITLIST_HONEYPOT=botcheck
PUBLIC_WAITLIST_FIELDS=access_key=<key>&subject=GotAuth%20waitlist&redirect=https%3A%2F%2Fgotauth.ablacky.com%2Fthanks%2F
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

Set `RESPONSE` on the mock to try each answer the script handles: `formspree` (the default, `200 {"ok": true}`), `web3forms` (`200 {"success": true}`), `reject` (`200 {"success": false}`, which the form must show as "not saved") and `text` (a plain-text 200, treated as success).

## Deploy to cPanel

The site is static: `pnpm build` writes everything to `dist/`, and any web server can serve that folder. It runs at **https://gotauth.ablacky.com** on cPanel (Apache). `public/.htaccess` ends up in `dist/` and sets HTTPS, the security headers, caching, compression and the 404 page. The Content-Security-Policy is a `<meta>` tag in every page, so it needs nothing from the server.

### One-time setup in cPanel
1. **Create the subdomain.** cPanel -> Domains -> Create A New Domain:
   - domain `gotauth.ablacky.com`
   - untick "Share document root"
   - document root, for example `gotauth.ablacky.com` (a folder in your home directory)

   If the DNS for `ablacky.com` is hosted on this cPanel, the DNS record is created for you. If it is hosted elsewhere, add an `A` record for `gotauth` pointing to the server's IP (cPanel shows it under "Shared IP Address" or "Dedicated IP"), or a `CNAME` to the server's hostname.
2. **HTTPS.** cPanel -> SSL/TLS Status -> select `gotauth.ablacky.com` -> Run AutoSSL. The certificate is usually issued within minutes once the DNS record resolves. Until then, the `.htaccess` redirect sends visitors to an HTTPS address that has no valid certificate.
3. **Waitlist form (optional).** Create a form on [Formspree](https://formspree.io) or [Web3Forms](https://web3forms.com) and note the values from "Environment variables" above. Use `https://gotauth.ablacky.com/thanks/` as the redirect address. Without a form backend the page shows "Waitlist opens soon".

### Build
From the repository root, in the dev container:

```bash
cp apps/landing/.env.example apps/landing/.env    # optional: fill in the PUBLIC_WAITLIST_* values
./dev.sh pnpm --dir apps/landing install --frozen-lockfile
./dev.sh pnpm --dir apps/landing run check         # builds dist/ and runs every check on it
```

### Upload by hand
1. Zip the **contents** of `apps/landing/dist` (not the folder itself), including the hidden `.htaccess`. For example: `cd apps/landing/dist && zip -r ../site.zip .`
2. cPanel -> File Manager -> open the document root (`gotauth.ablacky.com/`). Under Settings, tick "Show Hidden Files".
3. Delete the old site files there, but keep `.well-known/` and `cgi-bin/` if they exist. Then upload `site.zip`, right-click it -> Extract, and delete the zip.
4. Open https://gotauth.ablacky.com and https://gotauth.ablacky.com/no-such-page (it must show the 404 page).

### Upload automatically from GitHub (optional)
`.github/workflows/landing-deploy.yml` builds the site with the same checks as CI and uploads it over FTPS on every push to `main` that touches `apps/landing/`. It stays off until you turn it on:

1. **A dedicated FTP account.** cPanel -> FTP Accounts -> Add FTP Account. Set the directory to the document root (`gotauth.ablacky.com`) so the account can only write there. Under "Configure FTP Client", note the server hostname; use it instead of `gotauth.ablacky.com`, because the TLS certificate is issued for that name.
2. **The `landing` environment.** GitHub -> Settings -> Environments -> New environment `landing`. Under deployment branches, allow only `main`. Add these environment secrets:
   - `CPANEL_FTP_HOST`: the server hostname from step 1
   - `CPANEL_FTP_USER`: the full FTP user, for example `deploy@ablacky.com`
   - `CPANEL_FTP_PASSWORD`
3. **Repository variables.** Settings -> Secrets and variables -> Actions -> Variables:
   - `LANDING_DEPLOY` = `true`, which turns the workflow on
   - the `PUBLIC_WAITLIST_*` values and `PUBLIC_CONTACT_EMAIL`, if you use the form
   - `CPANEL_FTP_DIR`, only if the FTP account's home is not the document root
4. Run it once by hand: Actions -> Deploy landing page -> Run workflow.

The upload mirrors `dist/`: files that are no longer built are deleted on the server, except `.well-known/` and `cgi-bin/`. If your host has no FTPS, ask it to enable "explicit TLS" rather than sending passwords over plain FTP.

## Lighthouse

The brief asks for >= 95 in Performance, Accessibility, Best Practices and SEO, mobile and desktop, with the reports attached to the PR.

Measured locally on 2026-10-04 with Lighthouse 13.5.0 and headless Chromium 154, against `astro preview` in Docker. The same scores came from a build with a mock form endpoint and from the final build without one ("Waitlist opens soon"):

| | Performance | Accessibility | Best Practices | SEO |
|---|---|---|---|---|
| Mobile | 100 | 100 | 100 | 100 |
| Desktop | 100 | 100 | 100 | 100 |

Mobile LCP 0.8 to 1.3 s, desktop LCP 0.2 to 0.3 s, TBT 0 to 20 ms, CLS 0. The home page is 34 KB of HTML (about 9.5 KB gzipped) with CSS and the form script inline, and no other requests except the favicon.

Repeat it on the deployed site (the real host, with HTTPS, compression and headers):

- Chrome DevTools -> Lighthouse -> Mode: Navigation; Device: Mobile, then Desktop; all four categories -> Analyze. Save each report as HTML (menu -> Save as HTML) and attach it to the PR.
- Or [PageSpeed Insights](https://pagespeed.web.dev/) with https://gotauth.ablacky.com; it reports mobile and desktop.
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
