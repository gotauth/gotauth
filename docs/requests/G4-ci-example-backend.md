# G4: run the example backends' checks in CI

| | |
|---|---|
| From | G4 (examples) |
| For | F1 (`.github/workflows/ci.yml`) |
| Date | 2026-10-12 |

## What
Add a CI job for Python example backends. They are separate uv projects, not part of the root project, so `poe test` never runs their tests:
- `examples/fastapi-nextjs/backend/` now
- `examples/litestar-htmx/` and O2's `examples/fastmcp-server/` later

The frontends are already covered by the `node` job.

```yaml
  examples:
    name: Example backend (${{ matrix.project }})
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        project: [examples/fastapi-nextjs/backend]
    services:
      postgres: # same service block as the test job
    env:
      GOTAUTH_TEST_POSTGRES_URL: postgresql://gotauth:gotauth@localhost:5432/gotauth
      UV_PROJECT_ENVIRONMENT: .venv
    defaults:
      run:
        working-directory: ${{ matrix.project }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7 # v10.2.0
        with:
          version: ${{ env.UV_VERSION }}
          python-version: "3.14"
      - run: uv sync --locked
      - run: uv run pyright
      - run: uv run pytest
```

`ruff` for these folders already runs in the root `poe lint`. Each example's `pyproject.toml` extends the root ruff configuration.

## Why
`backend/tests/test_m2_scenario.py` is the M2 acceptance test, and it runs against SQLite and Postgres. Without this job, a library change that breaks the example only shows up when someone runs it by hand. In the meantime, the example's README and AGENTS.md give the command to run in the dev container.
