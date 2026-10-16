#!/usr/bin/env bash
# Run the end-to-end tests in Docker (work package Q2).
#
#   tests/e2e/run.sh              one run
#   tests/e2e/run.sh --repeat 3   three runs in a row, each on fresh containers
#   tests/e2e/run.sh -- -k mcp    extra pytest arguments after "--"
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

repeat=1
pytest_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --repeat) repeat="$2"; shift 2 ;;
    --) shift; pytest_args=("$@"); break ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

docker compose build

status=0
for run in $(seq 1 "$repeat"); do
  echo "=== e2e run $run of $repeat ==="
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker compose up --detach backend frontend
  if ! docker compose run --rm tests pytest tests/e2e -p no:cacheprovider \
      -o "addopts=--import-mode=importlib -ra" ${pytest_args[@]+"${pytest_args[@]}"}; then
    status=1
    docker compose logs frontend | tail -n 100
    echo "--- backend log ---"
    docker compose run --rm --no-deps -T tests tail -n 200 /logs/backend.log || true
  fi
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  [ "$status" -eq 0 ] || break
done
exit "$status"
