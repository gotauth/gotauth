# Docs site

The documentation at `gotauth.ablacky.com/docs`, with `llms.txt`, Markdown copies of every
page, the API reference and the agent skill. Work package G2.

## Choices

| What | Choice | Why |
|---|---|---|
| Generator | Material for MkDocs 9.7.7 on MkDocs 1.6.1 | Zensical was still 0.0.70 (alpha) on 2026-10-16; its dependable 0.1.0 line is announced for 2026-11-05. Material gets critical fixes until 2027-05-05. Moving to Zensical later keeps the Markdown |
| API reference | mkdocstrings 1.0.6 with mkdocstrings-python 2.0.9 (Google-style docstrings) | Generated from the code, so it can't drift |
| Token count | tiktoken 0.14.0, `o200k_base` | The quickstart must stay under 15,000 tokens so agents read it whole |
| Fonts | System fonts (`font: false`) | No request to Google Fonts, like the landing page: the site makes no third-party requests |

The versions are pinned by `uv.lock` (the `docs` dependency group).

## Layout

| Path | What it holds |
|---|---|
| `mkdocs.yml` | Site config and navigation |
| `docs/` | The hand-written pages: home, quickstart, concepts, guides, security, troubleshooting |
| `hooks.py` | Pages built from the module READMEs (`src/gotauth/**/README.md`) and `docs/launch/comparison.md`, with links rewritten; the API reference pages; a Markdown copy of every page; `llms.txt` and `llms-full.txt` |
| `docs/js/copy-markdown.js` | The "Copy page as Markdown" button |
| `tests/test_samples.py` | Runs every code sample of the hand-written pages and the skill (see below) |
| `tests/test_build.py` | Builds the site (or uses the one in `DOCS_SITE_DIR`, as CI does) and checks `llms.txt`, the Markdown copies, `robots.txt`, `sitemap.xml` and the skill's front matter |
| `scripts/count_tokens.py` | Fails when the quickstart reaches 15,000 tokens |
| `scripts/check_links.py` | Checks the external links of the built site, with retries. Links into this repository on GitHub are skipped: they come from files in the checkout, and a file added in the same pull request is not on main yet. In CI it is a separate job, so a third-party site that is down never blocks a deploy |
| `CONTEXT7.md` | How to list GotAuth on Context7 |
| `../../skills/gotauth/SKILL.md` | The agent skill (Agent Skills format) |

Plugin, integration and module pages come from each module's README, so a work
package updates its page by updating its README. Relative links in a README point to
the matching docs page, or to the file on GitHub.

## Commands

In the dev container:

```bash
./dev.sh uv sync --locked --all-extras --group docs
./dev.sh uv run --group docs mkdocs build -f apps/docs/mkdocs.yml        # strict: warnings fail
./dev.sh uv run --group docs pytest apps/docs/tests                       # samples and build checks
./dev.sh uv run --group docs python apps/docs/scripts/count_tokens.py
./dev.sh uv run --group docs python apps/docs/scripts/check_links.py      # after a build
```

Preview with live reload on http://localhost:8001/docs/ (Git Bash; the dev container's
`--ports` option publishes other ports):

```bash
COMPOSE_PROJECT_NAME=gotauth MSYS_NO_PATHCONV=1 docker compose run --rm -p 127.0.0.1:8001:8001 dev \
  uv run --group docs mkdocs serve -f apps/docs/mkdocs.yml -a 0.0.0.0:8001 --livereload
```

## Code samples

Every ` ```python ` block in `docs/` and in `SKILL.md` runs in CI, against
`gotauth.testing` or a SQLite file in a temporary directory. A comment on the line
before a block changes what happens:

| Marker | Effect |
|---|---|
| none, or `<!-- sample: run -->` | Runs the block; blocks of one page share a namespace |
| `<!-- sample: file=auth.py -->` | Writes the block to that file; later blocks import it |
| `<!-- sample: run -->` on a ` ```bash ` block | Runs its `gotauth ...` lines with the CLI |
| `<!-- sample: skip: <reason> -->` | Skips the block; the reason is required |

The Markdown copies and `llms.txt` leave the markers out.

## Agent readiness

- **`llms.txt`** (llmstxt.org format) lists every page with a one-line summary;
  **`llms-full.txt`** has all of them in one file. Both are built by `hooks.py`.
- **Markdown copies:** `/docs/quickstart/` is also `/docs/quickstart.md`; the home page
  is `/docs/index.md`.
- **The skill:** `skills/gotauth/SKILL.md`. Agents install it with
  `npx skills add gotauth/gotauth` (the skills.sh CLI; checked 2026-10-16), and skills.sh
  lists it once people install it.
- **Context7:** see `CONTEXT7.md`.
- **`robots.txt`** allows every crawler and names the sitemap. It is served at
  `/docs/robots.txt`; crawlers read the one at the site root, so the landing page's
  `robots.txt` names the docs sitemap too.

## Deploy

`.github/workflows/docs.yml` builds and tests the site on pull requests, and on `main`
uploads it to the same cPanel account as the landing page, into `docs/` under the
document root. It is off until the repository variable `DOCS_DEPLOY` is `"true"`, and uses
the same FTPS secrets as the landing page (`CPANEL_FTP_HOST`, `CPANEL_FTP_USER`,
`CPANEL_FTP_PASSWORD`) and `CPANEL_FTP_DIR`. The job runs in the GitHub environment
`docs`, and environment secrets are not shared between environments: create `docs`
(Settings -> Environments, deployment branches: `main` only) and add the same three
secrets there too. The landing page's deploy leaves `docs/` alone.
