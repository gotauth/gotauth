# The end-to-end test runner (work package Q2): Python Playwright with Chromium, the
# repository's own Python environment (the e2e group) and the MCP example's code.
# Built by tests/e2e/compose.yaml with the repository root as context.
FROM ghcr.io/astral-sh/uv:0.12.22 AS uv

# Keep the tag equal to the playwright version in uv.lock: the browsers must match.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble
COPY --from=uv /uv /bin/
ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /repo
COPY pyproject.toml uv.lock README.md LICENSE conftest.py ./
COPY src ./src
RUN uv sync --locked --all-extras --group e2e

COPY tests/conftest.py ./tests/
COPY tests/e2e ./tests/e2e
COPY examples/fastmcp-server/app ./examples/fastmcp-server/app

CMD ["pytest", "tests/e2e", "-p", "no:cacheprovider", "-o", "addopts=--import-mode=importlib -ra"]
