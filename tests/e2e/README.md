# End-to-end tests

Browser and protocol tests against the example apps. Work package Q2 owns this folder.

- Python Playwright (Chromium), run in Q2's own image built from the official Playwright Python image (`tests/e2e/Dockerfile`, `tests/e2e/run.sh`). The dev container has no browsers.
- Python dependencies come from the `e2e` dependency group: `uv sync --locked --all-extras --group e2e`.
- `poe test` and `poe check` skip this folder (`--ignore=tests/e2e`), and pyright excludes it, because the default environment does not install Playwright.
- Tests wait on page state, never on fixed sleeps, and must pass three runs in a row.
