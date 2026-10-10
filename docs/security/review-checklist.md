# Security review checklist

Apply this to every pull request for a security-critical work package (C1-C4, P1-P3, P6, O1-O3, Q1). It is also worth a pass on any change that touches `contracts/`, `crypto/` or `core/`. File each finding as `docs/requests/Q1-<wp>-<topic>.md`, or fix it before merge if it is in the PR's own write scope.

Answer each item with yes, no or n.a. A "no" blocks the merge unless a request file records it as accepted residual risk.

## Secrets
- [ ] Every new bearer secret has a registered prefix and is stored only as `crypto.hash_token(...)` (CONTRACTS 7, 8).
- [ ] Secrets are compared with `crypto.equal` or a hash lookup, never with `==`.
- [ ] No secret, password, OTP or provider token appears in a log line, an event, an error body, a `repr` or an exception message. `tests/security/test_raw_tokens.py` covers the new flow, or the PR adds it to the scenario.
- [ ] Values encrypted at rest use `crypto.encrypt` with their own `purpose`.
- [ ] Secrets are shown once: the create response only.

## Requests
- [ ] State-changing endpoints are POST, PATCH or DELETE. A GET that changes state is an OAuth callback or a one-time email link, protected by single-use state (AGENTS.md).
- [ ] Cookie-authenticated writes go through the origin check. Nothing opts out except bearer and API-key calls (10.1).
- [ ] Every redirect parameter goes through `validate_redirect` (10.1).
- [ ] Sensitive paths have a rate-limit rule, and email-addressed ones a per-email rule (10.2).
- [ ] Inputs are Pydantic models with `extra="forbid"` and length limits on strings.
- [ ] Errors use registered codes. No input value is echoed (6), and `error_format="oauth"` is set where an RFC requires it.

## Identity
- [ ] Unknown and known accounts get the same status and body, and no extra work on the request path (9.1). New email-addressed endpoints are added to `tests/security/test_enumeration.py`.
- [ ] New sessions come from `complete_sign_in` only, so the second-factor interceptors and the session rules apply.
- [ ] Account linking follows the CONTRACTS 11 matrix; no link is made on an unverified email.
- [ ] Changes to email, password or factors need a fresh session, end other sessions or offer to, and send a security notice.

## Tokens and OAuth
- [ ] JWTs are verified with the algorithm pinned per `kid`, and `typ`, `iss`, `aud` and `exp` are checked against the injected clock (12.2).
- [ ] Single-use values (codes, email tokens, OTPs, challenges) are consumed atomically: a second concurrent use fails.
- [ ] Reuse of a rotated refresh token revokes its family.
- [ ] Outbound fetches to user-supplied URLs pass the CIMD rules: https, public addresses only, pinned IP, no redirects, size and time limits (12.3).

## Failure behavior
- [ ] Any exception in a check denies access (fail closed). A resolver or hook that raises never lets a request through.
- [ ] Background work (email, events) cannot change the response, and its errors are logged without details.
- [ ] Transactions roll back on error, except for the failure events CONTRACTS 14 keeps.

## Tests
- [ ] Each threat the PR adds or changes has a row in [threat-model.md](threat-model.md) that links a test.
- [ ] The affected ASVS rows in [asvs.md](asvs.md) are updated.
- [ ] Tests that skipped in `tests/security/` waiting for this module are turned into real tests.
