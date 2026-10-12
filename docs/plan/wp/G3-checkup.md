# G3: `gotauth check` (front-door tool)

| | |
|---|---|
| Lane / wave | Growth / **Wave 1, late** (week 3; needs only F1) |
| Size | M |
| Depends on | F1 |
| Can start | after F1; no other work package needed |
| Write scope | `src/gotauth/checkup/**`, `tests/checkup/**`, `changes/G3.*.md` |
| Allowed new deps | none (stdlib `ast`) |

## Goal
A static checker that finds common Python auth mistakes and gives a 0-100 score, so `uvx gotauth check` is useful to people who never adopt GotAuth.

## Build
- `main(argv: Sequence[str] | None = None) -> int` and `__main__.py` (`python -m gotauth.checkup`). S1 wires `gotauth check` to it with a lazy import. Stdlib imports only.
- CLI: `[PATHS...] [--json | --sarif] [--fail-under N] [--select IDS] [--ignore IDS] [--exclude GLOB]`. Default `.`; skips `.git`, `.venv`, `venv`, `node_modules`, `site-packages`, `build`, `dist`.
- `ast.parse` per file; never import or execute scanned code. Unparsable files are listed as skipped. Suppression: `# gotauth: ignore[GA006]`.
- Rules, one visitor pass per file:

  | id | Sev | Finds |
  |---|---|---|
  | GA001 | high | `passlib` import |
  | GA002 | high | `jose` (python-jose) import |
  | GA003 | high | `jwt.encode` with HS256 and a literal secret or one < 32 chars |
  | GA004 | high | `jwt.decode` with signature verification off or no `algorithms=` |
  | GA005 | medium | `jwt.encode` payload dict without `exp` (heuristic) |
  | GA006 | medium | `==`/`!=` on names containing token, password, secret, signature, digest |
  | GA007 | medium | login-like POST route (path or function has login, signin, sign-in, token, password) and no slowapi, limits, fastapi-limiter or gotauth in the project |
  | GA008 | high | `verify=False` in httpx/requests calls or clients |
  | GA009 | high | high-entropy literal (>= 16 chars) assigned to `SECRET_KEY`, `JWT_SECRET`, `*_TOKEN`, `*_PASSWORD`-like names |
  | GA010 | high | `hashlib.md5/sha1/sha256` of a password-named value |
  | GA011 | medium | bcrypt cost < 10 (`gensalt(rounds=...)`, passlib `bcrypt__rounds`) |
  | GA012 | medium | `set_cookie(...)` without `httponly=True` or `secure=True` |
  | GA013 | high | CORS `allow_origins=["*"]` with `allow_credentials=True` |

- Finding: rule id, severity, `path:line:col`, message, fix hint. Hints are neutral (PyJWT with explicit algorithms, argon2-cffi or bcrypt, `hmac.compare_digest`, ...); GotAuth may be one option, never the only one.
- Score: 100 minus high 15, medium 6, low 2; each rule counts at most 3 times; floor 0.
- Output: text (grouped by file, score last), `--json` (stable schema with `version`), `--sarif` (SARIF 2.1.0 for GitHub code scanning, `helpUri` `https://gotauth.ablacky.com/check/<id>`).
- Exit codes: 0; 1 if score < `--fail-under`; 2 on usage errors.

## Acceptance tests
- Per rule: a positive fixture that triggers it and a negative (fixed) fixture that does not, in `tests/checkup/fixtures/<id>/`.
- Suppression silences only the named rule.
- SARIF output has the required SARIF 2.1.0 structure (`version`, `$schema`, `runs[].tool.driver.rules`, `results[].ruleId/level/locations`), checked field by field; JSON output matches a snapshot.
- `--fail-under 90` on a fixture scoring 70 exits 1.
- No network (`socket.socket` patched to raise). A fixture that raises on import is scanned without error, proving nothing is imported.
- Syntax errors and non-UTF-8 files are skipped, not crashes.
- 10k generated lines scan in < 2s in CI.
- Hypothesis: the score stays in 0-100 and never rises when a finding is added.

## Out of scope
The `gotauth` CLI entry point (S1), per-rule docs pages (G2), launch posts and the clip (G5).

## Notes
- No telemetry. Usage is measured only by PyPI downloads.
- Before release, check the current maintenance status of passlib and python-jose and word GA001/GA002 from what you find, linking the source in the rule doc.
- Heuristic rules (GA005-GA007) stay at medium so false positives are cheap.
- `uvx gotauth check` must work with no extras installed. S1's brief requires `gotauth.cli` to import extras lazily; G3 adds a test that importing `gotauth.checkup` loads only the standard library and `gotauth` itself.
