#!/usr/bin/env bash
# The agent-install test (work package Q2): Claude Code adds auth to a fresh FastAPI app,
# and checker/ judges the result. Pass rule: every run green (3 of 3 by default).
#
#   ANTHROPIC_API_KEY=... scripts/agent-install-test/run.sh               3 runs with the skill
#   ANTHROPIC_API_KEY=... scripts/agent-install-test/run.sh --baseline    without skill and llms.txt;
#                                                                          writes docs/launch/agent-baseline.md
#   scripts/agent-install-test/run.sh --runs 1
#
# Your key is passed to the container at run time only: never in the image, the logs
# or the results. Results (transcripts, diffs, checker reports) go to
# scripts/agent-install-test/results/<time>/, which git ignores.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

runs=3
baseline=0
prompt="Add email + password and GitHub login and API keys to this FastAPI app."
while [ $# -gt 0 ]; do
  case "$1" in
    --runs) runs="$2"; shift 2 ;;
    --baseline) baseline=1; shift ;;
    --prompt) prompt="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "Set ANTHROPIC_API_KEY (your own key) in the environment first." >&2
  exit 2
fi
# Nothing that looks like a credential may sit in the build context.
found="$(find "$here" -path "$here/results" -prune -o \( -name '.env*' -o -name '*.pem' -o -name '*.key' \
  -o -name '.credentials.json' -o -name '.claude.json' -o -name 'credentials*' \) -print)"
if [ -n "$found" ]; then
  echo "Refusing to run: credential-like files in the build context:" >&2
  echo "$found" >&2
  exit 2
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mode=$([ "$baseline" -eq 1 ] && echo baseline || echo skill)
out="$here/results/$stamp-$mode"
mkdir -p "$out/wheels"

echo "Building the gotauth wheel from this checkout"
(cd "$root" && ./dev.sh uv build --wheel --out-dir "scripts/agent-install-test/results/$stamp-$mode/wheels" >/dev/null)
if [ "$baseline" -eq 0 ]; then
  echo "Building llms.txt (docs site)"
  (cd "$root" && ./dev.sh uv run --group docs mkdocs build -q -f apps/docs/mkdocs.yml >/dev/null 2>&1)
  cp "$root/apps/docs/site/llms.txt" "$out/llms.txt"
fi

image="gotauth-agent-install-test"
docker build -q -t "$image" "$here" >/dev/null
version="$(docker run --rm "$image" claude --version)"
echo "Claude Code: $version"

passed=0
for i in $(seq 1 "$runs"); do
  run="$out/run-$i"
  mkdir -p "$run"
  cp -r "$here/template" "$run/app"
  if [ "$baseline" -eq 0 ]; then
    mkdir -p "$run/app/.claude/skills/gotauth"
    cp "$root/skills/gotauth/SKILL.md" "$run/app/.claude/skills/gotauth/SKILL.md"
    cp "$out/llms.txt" "$run/app/llms.txt"
  fi
  echo "=== run $i of $runs ($mode) ==="
  docker run --rm -e ANTHROPIC_API_KEY \
    -e PROMPT="$prompt" \
    -v "$run:/work" -v "$out/wheels:/wheels:ro" -v "$here/checker:/checker:ro" \
    "$image" bash -c '
      set -u
      cd /work/app
      git init -q && git add -A && git -c user.email=t@t -c user.name=template commit -qm template
      claude -p "$PROMPT" --output-format stream-json --verbose \
        --permission-mode acceptEdits --max-turns 80 \
        --allowedTools "Read Write Edit Glob Grep Bash(uv:*) Bash(uvx:*) Bash(python:*) Bash(ls:*) Bash(cat:*) Bash(mkdir:*)" \
        > /work/transcript.jsonl 2> /work/claude.err || true
      git add -A && git diff --cached HEAD > /work/diff.patch
      uv sync -q 2> /work/sync.err || true
      python /checker/check.py /work/app --json /work/check.json | tee /work/check.txt
    ' && passed=$((passed + 1)) || true
  # Never keep a key in what we save.
  if grep -rlF "$ANTHROPIC_API_KEY" "$run" >/dev/null 2>&1 || grep -rlE 'sk-ant-[A-Za-z0-9_-]{20,}' "$run" >/dev/null 2>&1; then
    echo "A credential appeared in run $i's files: deleting them." >&2
    rm -rf "$run"
  fi
done

python3 "$here/report.py" "$out" --cli-version "$version" --mode "$mode" \
  $([ "$baseline" -eq 1 ] && echo "--write $root/docs/launch/agent-baseline.md")
echo "$passed of $runs runs passed ($mode). Results: $out"
[ "$passed" -eq "$runs" ]
