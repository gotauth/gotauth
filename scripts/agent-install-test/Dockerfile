# The agent-install test (work package Q2): Claude Code, Python and uv, nothing else.
# Credentials are never baked in: run.sh passes ANTHROPIC_API_KEY at run time.
FROM ghcr.io/astral-sh/uv:0.12.22 AS uv
FROM node:24.21.0-trixie-slim AS node

FROM python:3.14.8-slim-trixie
COPY --from=uv /uv /uvx /bin/
COPY --from=node /usr/local/bin/node /usr/local/bin/
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && apt-get update -qq && apt-get install -y -qq --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pinned: released 2026-10-01. Record a newer version in agent-baseline.md when it changes.
ARG CLAUDE_CODE_VERSION=2.1.287
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"

ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --create-home agent
USER agent
WORKDIR /work/app
