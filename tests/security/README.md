# Security tests

Cross-module security tests: account enumeration, CSRF and origin checks, redirect validation, token handling, rate limits and the other items in the threat model (`docs/security/`). Work package Q1 owns this folder.

- They run in `poe test` and in CI like every other test.
- Timing comparisons carry the `timing` marker. `poe test` leaves them out, because they are sensitive to machine load; Q1 runs them in a separate CI job with `pytest -m timing tests/security`.
- Findings in other modules go to their owners as request files (`docs/requests/Q1-<topic>.md`), not as direct fixes.
