# Docs site

The documentation site for `gotauth.dev/docs`, with `llms.txt`, Markdown copies of every page and the API reference. Work package G2 owns this folder and records its choices here.

- Generator: Material for MkDocs or Zensical, decided by G2 at build time. The Python dependencies are in the `docs` dependency group: `./dev.sh uv sync --locked --all-extras --group docs`.
- API reference from the Google-style docstrings through mkdocstrings.
- Code samples on every page run in CI against `gotauth.testing` (`apps/docs/tests/test_samples.py`).
- Build and preview in the dev container; publish the preview port with `./dev.sh --ports` and serve on `0.0.0.0:8000`.
- The deploy workflow is `.github/workflows/docs.yml` (G2).
- If the site has a `package.json`, it is a Node project (CONTRIBUTING.md, "Node projects"): its own `pnpm-lock.yaml`, `"packageManager": "pnpm@12.8.1"`, and a `check` script that CI runs after `pnpm install --frozen-lockfile`. The same convention applies to every `apps/<name>/` folder.
