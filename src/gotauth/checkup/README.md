# gotauth check

A static scanner for risky hand-written Python auth code. It gives a score from 0 to 100 and is useful whether or not you use GotAuth.

- It reads and parses files with `ast` only. It never imports or runs the scanned code, opens no network connection and sends no telemetry.
- It needs only the standard library, so `uvx gotauth check` works without any extras.
- Rules: see [Rules](#rules) below. The docs site will publish one page per rule at `https://gotauth.dev/check/<id>` (work package G2).

## Usage

```bash
uvx gotauth check                      # scan the current folder
gotauth check src tests --fail-under 80
python -m gotauth.checkup src --json   # same tool without the console script
gotauth check --sarif > gotauth.sarif  # for GitHub code scanning
```

```text
gotauth check [PATHS...] [--json | --sarif] [--fail-under N]
              [--select IDS] [--ignore IDS] [--exclude GLOB]
```

| Option | Meaning |
|---|---|
| `PATHS` | Files or folders (default `.`). Folders are walked for `*.py` files. |
| `--json` | JSON output with a stable schema (`"version": 1`). |
| `--sarif` | SARIF 2.1.0 for GitHub code scanning. |
| `--fail-under N` | Exit with code 1 when the score is below `N`. |
| `--select IDS`, `--ignore IDS` | Run only, or leave out, these rules (comma-separated, repeatable). |
| `--exclude GLOB` | Leave out matching files and folders, for example `tests` or `*_test.py` (repeatable). |

Exit codes: `0` done, `1` score below `--fail-under`, `2` usage error.

While walking a folder, the scanner skips `.git`, `.venv`, `venv`, `node_modules`, `site-packages`, `build`, `dist`, `__pycache__`, hidden folders, `*.egg-info` and any folder with a `pyvenv.cfg`. Files that are not valid UTF-8, do not parse, or are larger than 5 MiB are listed as skipped.

Test code often holds sample secrets on purpose. If that makes noise, add `--exclude tests`.

### From Python

```python
from gotauth.checkup import format_json, scan

report = scan(["src"], ignore=["GA007"])
for finding in report.findings:
    print(finding.location, finding.rule_id, finding.message)
print(report.score)
print(format_json(report))
```

`main(argv) -> int` is the command line entry point (`gotauth check` calls it).

## Suppressing a finding

Put a comment on the line the finding points to. It silences only the named rules:

```python
if digest == signature:  # gotauth: ignore[GA006]
```

Several ids: `# gotauth: ignore[GA006, GA012]`.

## Rules

| Id | Severity | Finds |
|---|---|---|
| GA001 | high | `passlib` import |
| GA002 | high | `jose` (python-jose) import |
| GA003 | high | `jwt.encode` with HS256 (or omitted algorithm, or another HS algorithm) and a hard-coded secret, or a secret that falls back to a literal `os.getenv` default |
| GA004 | high | `jwt.decode` with signature verification off, without `algorithms=`, with `algorithms=None`, or accepting `"none"` |
| GA005 | medium | `jwt.encode` payload dict without `exp` (heuristic: dict literals in the same function) |
| GA006 | medium | `==` or `!=` on names with the words token, password, secret, signature, digest (and api key, hmac, otp); `assert` statements are ignored |
| GA007 | medium | POST route whose path or function mentions login, sign-in, token or password, while no scanned file or dependency file uses slowapi, limits, fastapi-limiter, Flask-Limiter, django-ratelimit or gotauth |
| GA008 | high | `verify=False` for requests or httpx calls, clients and sessions (also `session.verify = False`) |
| GA009 | high | High-entropy literal (16+ characters) assigned to `SECRET_KEY`, `JWT_SECRET`, `*_TOKEN`, `*_PASSWORD`, `*_API_KEY`-like names, config keys or keyword arguments |
| GA010 | high | `hashlib.md5`, `sha1`, `sha256` (and other fast hashes) of a password-named value |
| GA011 | medium | bcrypt cost below 10 (`gensalt(rounds=...)`, passlib `bcrypt__rounds`, pwdlib `BcryptHasher`, `BCRYPT_LOG_ROUNDS`) |
| GA012 | medium | `set_cookie(...)` without `httponly=True` or `secure=True` (CSRF cookies may skip HttpOnly) |
| GA013 | high | CORS with `allow_origins=["*"]` (or a match-all regex) and `allow_credentials=True` |

Heuristic rules (GA005 to GA007) stay at medium so a false positive costs little. When a value is not a literal the scanner can see, the rules assume the code is fine.

### Facts behind GA001 and GA002 (checked 2026-10)

- passlib: last release 1.7.4 on 2020-10-08 ([PyPI](https://pypi.org/project/passlib/)). With bcrypt 4.1.1 and later its bcrypt backend logs an error reading the bcrypt version ([pyca/bcrypt#684](https://github.com/pyca/bcrypt/issues/684), still open). The FastAPI docs replaced it with pwdlib in September 2025 ([fastapi#13917](https://github.com/fastapi/fastapi/pull/13917)).
- python-jose: no release between 3.3.0 (2021-06-05) and 3.4.0 (2025-02-18); 3.5.0 followed on 2025-05-28 ([PyPI](https://pypi.org/project/python-jose/)). CVE-2024-33663 ([GHSA-6c5p-j8vq-pqhj](https://github.com/advisories/GHSA-6c5p-j8vq-pqhj)) and CVE-2024-33664 ([GHSA-cjwg-qfpm-7377](https://github.com/advisories/GHSA-cjwg-qfpm-7377)) were fixed in 3.4.0. The FastAPI docs replaced it with PyJWT in May 2024 ([fastapi#11589](https://github.com/fastapi/fastapi/pull/11589)).
- GA013: Starlette's `CORSMiddleware` echoes the request `Origin` when `"*"` is combined with `allow_credentials=True` (checked against Starlette 1.7.0).

## Score

100 minus 15 per high, 6 per medium and 2 per low finding. Each rule counts at most 3 times; the score never goes below 0.

## Output formats

- **Text:** findings grouped by file with a fix hint each, then a summary line and `Score: N/100` last.
- **JSON:** `{"version": 1, "tool", "score", "summary", "findings", "skipped"}`. Each finding has `rule_id`, `severity`, `path`, `line`, `column` (1-based), `end_line`, `end_column` (just after the end, as in SARIF), `message`, `hint`, `help_uri` and `fingerprint`. Messages never contain the secret value.
- **SARIF 2.1.0:** `$schema`, `version`, one run with `tool.driver.rules` (id, name, descriptions, help, `helpUri` `https://gotauth.dev/check/<id>`, level, `security-severity`), results with `ruleId`, `ruleIndex`, `level`, `message`, `locations` (relative to `%SRCROOT%`) and `partialFingerprints`. Skipped files appear as tool execution notifications. Validated against the SARIF 2.1.0 JSON schema.

GitHub Actions example:

```yaml
- run: uvx gotauth check --sarif > gotauth.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: gotauth.sarif
```
