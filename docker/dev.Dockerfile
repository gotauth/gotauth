# syntax=docker/dockerfile:1
#
# GotAuth dev image: Python 3.14 with uv, Node 24 with pnpm (through corepack).
# Every uv, python, pytest, ruff, pyright, pnpm and node command runs in this image
# (AGENT-RULES section 6). Use it through ./dev.sh or .\dev.ps1, see CONTRIBUTING.md.
#
# Pinned versions. Update them together with CONTRIBUTING.md, .github/workflows/ci.yml
# (uv) and the "packageManager" field of every package.json (pnpm).

FROM ghcr.io/astral-sh/uv:0.12.22 AS uv
FROM node:24.21.0-trixie-slim AS node

FROM python:3.14.8-slim-trixie

ARG PNPM_VERSION=12.8.1
ARG USER_NAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

COPY --from=uv /uv /uvx /bin/

# Node from the official image. Only node, npm and corepack are copied, so the Python
# installation in /usr/local stays untouched.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && ln -s ../lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_CACHE_DIR=/opt/uv-cache \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON_PREFERENCE=only-system \
    COREPACK_HOME=/opt/corepack \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    COREPACK_DEFAULT_TO_LATEST=0 \
    pnpm_config_store_dir=/opt/pnpm-store \
    pnpm_config_update_notifier=false \
    PYRIGHT_PYTHON_IGNORE_WARNINGS=1

# "pnpm --version" fetches the native pnpm binary into COREPACK_HOME now, not on every
# container start. The mount points exist in the image and belong to the dev user, so
# new volumes mounted there start with the right owner.
RUN groupadd --gid "${USER_GID}" "${USER_NAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash "${USER_NAME}" \
    && corepack enable pnpm \
    && corepack install --global "pnpm@${PNPM_VERSION}" \
    && pnpm --version \
    && mkdir -p /opt/venv /opt/uv-cache /opt/pnpm-store "/home/${USER_NAME}/.cache" /workspace \
    && chown -R "${USER_UID}:${USER_GID}" /opt/venv /opt/uv-cache /opt/pnpm-store /opt/corepack \
        "/home/${USER_NAME}/.cache" /workspace

USER ${USER_NAME}
WORKDIR /workspace
CMD ["bash"]
