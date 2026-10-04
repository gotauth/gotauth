#!/usr/bin/env bash
# Run a command in the GotAuth dev container (Git Bash, Linux, macOS).
#
#   ./dev.sh uv sync --locked --all-extras
#   ./dev.sh uv run poe check
#   ./dev.sh                      interactive shell
#   ./dev.sh --ports <command>    also publish the dev server ports on 127.0.0.1
#   ./dev.sh --build <command>    rebuild the image first (after changes in docker/)
#   ./dev.sh --down               stop this worktree's containers (volumes are kept)
#
# The Compose project name is this folder's name, so each git worktree gets its own
# containers, virtual environment, Postgres and Redis. PowerShell: .\dev.ps1
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

# Same normalization as Compose: lower case, only [a-z0-9_-], no leading "_" or "-".
project="$(basename "$root" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-' | sed 's/^[_-]*//')"
export COMPOSE_PROJECT_NAME="${project:-gotauth}"

# Keep Git Bash (MSYS) from rewriting container paths such as /workspace.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

run_args=(--rm)
build=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ports) run_args+=(--service-ports); shift ;;
    --build) build=1; shift ;;
    --down) exec docker compose down --remove-orphans ;;
    --) shift; break ;;
    *) break ;;
  esac
done

# Shared caches (see compose.yaml). "docker volume create" is a no-op if they exist.
docker volume create gotauth-uv-cache >/dev/null
docker volume create gotauth-pnpm-store >/dev/null

if [ "$build" -eq 1 ]; then
  docker compose build dev
fi

# No TTY when input or output is redirected (agents, CI, pipes).
if [ ! -t 0 ] || [ ! -t 1 ]; then
  run_args+=(-T)
fi

if [ $# -eq 0 ]; then
  set -- bash
fi

exec docker compose run "${run_args[@]}" dev "$@"
