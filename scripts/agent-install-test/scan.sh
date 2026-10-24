# The leak scan, sourced by run.sh on the host and inside the container, so both scans
# are the same. `leaked DIR` succeeds when DIR holds the credential (in $credential,
# when set) or anything shaped like a key or token: API keys and subscription tokens
# both start with sk-ant-. It looks at file contents and file names.
#
# The credential goes to grep on stdin, never argv, so it stays out of the process
# list. It fails closed: a file grep cannot read counts as a match. The shape check
# skips .venv and node_modules, where packages ship sample keys; the exact check does
# not.
leaked() {
  local dir="$1" status=0 name
  if [ -n "${credential:-}" ]; then
    printf '%s\n' "$credential" | grep -rqF -f /dev/stdin "$dir" 2>/dev/null || status=$?
    [ "$status" -ne 1 ] && return 0
    status=0
  fi
  grep -rqE --exclude-dir=.venv --exclude-dir=node_modules 'sk-ant-[A-Za-z0-9_-]{20,}' \
    "$dir" 2>/dev/null || status=$?
  [ "$status" -ne 1 ] && return 0
  while IFS= read -r name; do
    if [ -n "${credential:-}" ] && [[ "$name" == *"$credential"* ]]; then
      return 0
    fi
    [[ "$name" =~ sk-ant-[A-Za-z0-9_-]{20,} ]] && return 0
  done < <(find "$dir" 2>/dev/null)
  return 1
}
