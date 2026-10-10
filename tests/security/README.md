# Security tests

Cross-module attack tests for the threats in [docs/security/threat-model.md](../../docs/security/threat-model.md). Work package Q1 owns this folder. `conftest.py` builds `full_app()`: a GotAuth with every merged module, plus browser-like clients that can set the client IP and the `Origin` header.

| File | Covers |
|---|---|
| `test_enumeration.py` | Same body for known and unknown emails; timing (`timing` marker) |
| `test_requests.py` | Origin and CSRF checks, content types, open redirects, session fixation, cookie flags |
| `test_raw_tokens.py` | No raw secret in any table or GotAuth log line after a full scenario on SQLite |
| `test_limits_and_replay.py` | Rate limits and replay of codes, refresh tokens and email tokens |
| `test_oauth.py` | OAuth attacks that O1's own suite does not cover |
| `test_fuzz.py` | Hypothesis input for every HTTP endpoint: no 500, no echoed values, the documented error shape |

**How they run:**
- They run in `poe test` and in CI like every other test, and again in `.github/workflows/security.yml`.
- **Timing tests** carry the `timing` marker. `poe test` leaves them out, because they are sensitive to machine load. The security workflow runs them with `pytest -m timing tests/security`, with retries; that job is not a merge blocker.
- **Modules that have not merged** (P2-P6) have skipped tests that name the module. Turn them into real tests when it lands.

**Self-tests.** `test_scan_catches_a_raw_token_stored_on_purpose` and `test_the_harness_catches_a_crashing_endpoint` prove that the scan and the fuzz checks can fail.

**Findings** in other modules go to their owners as request files (`docs/requests/Q1-<wp>-<topic>.md`), not as direct fixes.
