#!/usr/bin/env bash
# The agent-install test (work package Q2): Claude Code adds auth to a fresh FastAPI app,
# and checker/ judges the result. Pass rule: every run green (3 of 3 by default).
#
#   CLAUDE_CODE_OAUTH_TOKEN=... scripts/agent-install-test/run.sh             3 runs with the skill
#   CLAUDE_CODE_OAUTH_TOKEN=... scripts/agent-install-test/run.sh --baseline  without skill and llms.txt;
#                                                                              writes docs/launch/agent-baseline.md
#   scripts/agent-install-test/run.sh --runs 1
#
# The credential is a Claude subscription token (`claude setup-token`) or an API key
# (ANTHROPIC_API_KEY). It is passed to the container at run time only, and only to
# Claude Code: never in the image, the logs or the results. Results (transcripts, diffs, checker reports)
# go to scripts/agent-install-test/results/<time>/, which git ignores.
set -euo pipefail
set +x  # never trace: the credential is in a variable

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
# A path Docker understands: on Git Bash for Windows, C:/... instead of /c/...
dpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

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

# One credential, by name. Claude Code prefers an API key when both are set, so a
# subscription token is used only on its own.
if [ -n "${ANTHROPIC_API_KEY:-}" ] && [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
  echo "Set only one of ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN." >&2
  exit 2
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  credential_var=ANTHROPIC_API_KEY
elif [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
  credential_var=CLAUDE_CODE_OAUTH_TOKEN
else
  echo "Set CLAUDE_CODE_OAUTH_TOKEN (from \`claude setup-token\`, your Claude subscription)" >&2
  echo "or ANTHROPIC_API_KEY (your own key) in the environment first." >&2
  exit 2
fi
credential="${!credential_var}"
# A pasted line break or space would break the sign-in and the leak scan.
if ! [[ "$credential" =~ ^sk-ant-[A-Za-z0-9_-]+$ ]]; then
  echo "$credential_var does not look like a key or token (sk-ant-...): check for spaces or line breaks." >&2
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
wheel="$(basename "$(ls "$out"/wheels/gotauth-*.whl | head -n 1)")"
if [ "$baseline" -eq 0 ]; then
  echo "Building llms.txt (docs site)"
  (cd "$root" && ./dev.sh uv run --group docs mkdocs build -q -f apps/docs/mkdocs.yml >/dev/null 2>&1)
  cp "$root/apps/docs/site/llms.txt" "$out/llms.txt"
fi

image="gotauth-agent-install-test"
docker build -q -t "$image" "$(dpath "$here")" >/dev/null
version="$(docker run --rm "$image" claude --version)"
echo "Claude Code: $version"

# The leak scan (scan.sh), the same here and inside the container. A run whose files
# hold the credential, or anything shaped like one, is deleted and fails.
# shellcheck source=scan.sh
. "$here/scan.sh"
scrub() {
  # As root in the image: the container's user owns most of these files.
  docker run --rm --user 0 -v "$(dpath "$1"):/r" "$image" find /r -mindepth 1 -delete \
    >/dev/null 2>&1 || rm -rf "${1:?}"/* 2>/dev/null || true
  printf '[{"name": "no credential in the results", "passed": false, "detail": "the files were deleted"}]\n' \
    > "$1/check.json"
}
warn_leak() {
  echo "A credential, or something shaped like one, appeared in run $1's files: they were" >&2
  echo "deleted and the run failed. Treat the credential as exposed (README, \"What the agent can see\")." >&2
}
current=""
on_interrupt() {
  trap - INT TERM HUP
  echo "Interrupted: stopping the run and scanning what it wrote." >&2
  if [ -n "$current" ]; then docker rm -f "$current" >/dev/null 2>&1 || true; fi
  for dir in "$out"/run-*; do
    if [ -d "$dir" ] && leaked "$dir"; then scrub "$dir"; warn_leak "${dir##*-}"; fi
  done
  exit 130
}
trap on_interrupt INT TERM HUP

passed=0
for i in $(seq 1 "$runs"); do
  run="$out/run-$i"
  mkdir -p "$run"
  cp -r "$here/template" "$run/app"
  if [ "$baseline" -eq 0 ]; then
    mkdir -p "$run/app/.claude/skills/gotauth"
    cp "$root/skills/gotauth/SKILL.md" "$run/app/.claude/skills/gotauth/SKILL.md"
    cp "$out/llms.txt" "$run/app/llms.txt"
    # The current build in place of a release on PyPI. Only with the skill: the
    # baseline app must not hint at GotAuth.
    printf '\n[tool.uv.sources]\ngotauth = { path = "/wheels/%s" }\n' "$wheel" >> "$run/app/pyproject.toml"
  fi
  # The container's user writes here, whatever the host's user id is.
  chmod -R a+rwX "$run"
  echo "=== run $i of $runs ($mode) ==="
  current="gotauth-agent-install-$stamp-$i"
  # The credential goes in on stdin: it is never in the container's environment, so
  # not in `docker inspect` or /proc/1/environ. In the background, so that Ctrl-C runs
  # the trap at once instead of after the container ends.
  printf '%s\n' "$credential" | docker run --rm -i --init --name "$current" \
    --cap-drop ALL --security-opt no-new-privileges \
    -e CREDENTIAL_VAR="$credential_var" -e PROMPT="$prompt" \
    -v "$(dpath "$run"):/work" -v "$(dpath "$out/wheels"):/wheels:ro" \
    -v "$(dpath "$here/checker"):/checker:ro" -v "$(dpath "$here/scan.sh"):/scan.sh:ro" \
    "$image" bash -c '
      set -uo pipefail
      IFS= read -r credential
      . /scan.sh
      scrub() {
        find /work -mindepth 1 -delete
        printf "%s\n" "[{\"name\": \"no credential in the results\", \"passed\": false, \"detail\": \"the files were deleted\"}]" > /work/check.json
        echo "A credential, or something shaped like one, appeared in the run files: deleted." >&2
        exit 3
      }
      cd /work/app
      # Bind-mounted files can look owned by another user (Docker Desktop on Windows).
      git config --global --add safe.directory /work/app
      git init -q && git add -A && git -c user.email=t@t -c user.name=template commit -qm template
      # Only the claude process gets the credential. The commands it runs for the agent
      # inherit it: the Claude Code subprocess scrub needs bubblewrap, which cannot make
      # namespaces in a default Docker container (README, "What the agent can see").
      (
        export "$CREDENTIAL_VAR=$credential"
        exec claude -p "$PROMPT" --output-format stream-json --verbose \
          --permission-mode acceptEdits --max-turns 80 \
          --allowedTools "Read Write Edit Glob Grep Bash(uv:*) Bash(uvx:*) Bash(python:*) Bash(ls:*) Bash(cat:*) Bash(mkdir:*)" \
          < /dev/null > /work/transcript.jsonl 2> /work/claude.err
      ) || true
      # Anything the agent left running (a server started with &) still holds the
      # credential in its environment: end every other process of this user.
      kill -KILL -1 2>/dev/null || true
      if leaked /work; then scrub; fi
      unset credential
      git add -A && git diff --cached HEAD > /work/diff.patch
      uv sync -q 2> /work/sync.err || true
      python /checker/check.py /work/app --json /work/check.json > /work/check.txt
      code=$?
      if leaked /work; then scrub; fi
      chmod -R a+rX /work 2>/dev/null || true  # so the host can scan every file
      cat /work/check.txt
      exit "$code"
    ' &
  status=0
  wait $! || status=$?
  current=""
  run_ok=0
  [ "$status" -eq 0 ] && run_ok=1
  if [ "$status" -eq 3 ]; then
    warn_leak "$i"
  elif leaked "$run"; then  # anything that got past the scan in the container
    scrub "$run"
    warn_leak "$i"
    run_ok=0
  fi
  passed=$((passed + run_ok))
done

report_args=()
if [ "$baseline" -eq 1 ]; then
  report_args=(-v "$(dpath "$root/docs/launch"):/launch")
fi
write_args=()
if [ "$baseline" -eq 1 ]; then
  write_args=(--write /launch/agent-baseline.md)
fi
docker run --rm -v "$(dpath "$out"):/results" -v "$(dpath "$here/report.py"):/report.py:ro" \
  "${report_args[@]+"${report_args[@]}"}" \
  "$image" python /report.py /results --cli-version "$version" --mode "$mode" --prompt "$prompt" \
  "${write_args[@]+"${write_args[@]}"}"
echo "$passed of $runs runs passed ($mode). Results: $out"
[ "$passed" -eq "$runs" ]
