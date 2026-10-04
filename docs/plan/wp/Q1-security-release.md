# Q1: Security hardening + release pipeline

| | |
|---|---|
| Lane / wave | Quality / **Wave 3**, with reviews from Wave 1 |
| Size | L |
| Depends on | C1-C4, S1, O1 (tests for unmerged modules are skipped with a reason) |
| Can start | checklist and threat model at M0; tests as each module merges |
| Write scope | `tests/security/**`, `docs/security/**`, `docs/requests/Q1-*.md`, `.github/workflows/release.yml`, `.github/workflows/security.yml`, `SECURITY.md` (replaces F1's stub), `changes/Q1.*.md` |
| Allowed new deps | dev only: pip-audit (added up front by F1) |

## Goal
Make the security claims checkable: a threat model, an ASVS mapping, tests that attack every flow, supply-chain checks, and releases with provenance.

## Build
- `docs/security/threat-model.md`: STRIDE per flow (email/password, sessions, social login, OAuth server, MCP resource servers, API keys, agents): assets, trust boundaries, threats, mitigations with CONTRACTS refs, the test proving each, residual risk (e.g. cookie cache revocation delay, section 7; remote JWT-only acceptance until expiry, 12.2).
- `docs/security/asvs.md`: OWASP ASVS 5.0 Level 2 table (id, met / partial / n.a., where, test). Core chapters: V6 Authentication, V7 Session Management, V8 Authorization, V9 Self-contained Tokens, V10 OAuth and OIDC, V11 Cryptography.
- `docs/security/review-checklist.md`, applied to C1-C4 and O1 PRs as they land; findings filed as `docs/requests/Q1-<wp>-<topic>.md`.
- `tests/security/` (real crypto, `make_auth` / `make_client`):
  - enumeration: same status and body for known and unknown emails (sign-in, sign-up, reset, verification, magic link, OTP, invitations); timing within a tolerance (two-sample test over >= 200 runs, `timing` marker, own CI job) with a non-localhost `base_url`, so email goes out in the background (section 9); `auth.drain()` after each batch.
  - origin/CSRF (10.1): cookie POST without Origin, wrong, `null`, Referer fallback; bearer exempt; form-encoded posts to `input_format="json"` endpoints -> `UNSUPPORTED_MEDIA_TYPE`; cookie POST to the form endpoint `oauth_consent` without a trusted Origin rejected. Open redirect: `//evil`, `/\evil`, `https:evil`, `javascript:`, userinfo, wildcard edges.
  - session fixation: a planted cookie is never adopted; sign-in and 2FA completion (`finish_challenge`) issue new tokens. Cookie flags: HttpOnly, Secure, SameSite, `__Secure-` on https.
  - raw-token scan: full scenario on SQLite, dump every table and captured logs; fail on any `gas_` / `gak_` / `gar_` / `gac_` / `gav_` / `gcs_` value, any plain OTP or any raw token seen during the run.
  - rate limits: defaults hit, `Retry-After`, spoofed `X-Forwarded-For` ignored without `trusted_proxies`; per-email limits (10.2) hold across rotating IPs on `/sign-in/email`, `/request-password-reset`, `/magic-link/send`, `/email-otp/send`.
  - replay: auth codes, refresh tokens (family revoked), verification tokens, OTPs, TOTP steps, backup codes, passkey challenges, invitations.
  - bans (when P6 merges): a banned user's session, API key and OAuth token are rejected by P6's `PrincipalCheck`.
  - OAuth: PKCE missing / `plain` / wrong verifier; `redirect_uri` tricks; CIMD SSRF (loopback, RFC 1918, 169.254.169.254, IPv6 ULA, IPv4-mapped, redirects, DNS rebinding, > 5 KB, > 5s); JWT alg confusion (`none`, HS256 with the public key, wrong `typ` / `aud` / `iss`, unknown `kid`); revoked token rejected in-process on the next call.
  - Hypothesis fuzzing of every registered endpoint's input model: never 500, never echoes input, error shape per section 6 (RFC 6749 shape on `error_format="oauth"` endpoints: `oauth_token`, `oauth_introspect`, `oauth_revoke`).
- `security.yml`: adapter conformance on memory, SQLite and Postgres; pip-audit; actions pinned by commit SHA. F1 already pins its own workflows by SHA and enables ruff `S` rules in `pyproject.toml`; file `docs/requests/Q1-ci.md` only if something is missing.
- OpenID conformance: `docs/security/conformance/README.md` (Docker steps for the OpenID Foundation suite, using O1's `conformance/` app and plan config) and results in `docs/security/conformance/O1-<date>.md`.
- `release.yml` (actions pinned by SHA): tag `v*` -> tests -> `uv build` -> PyPI trusted publishing with `pypa/gh-action-pypi-publish` (PEP 740 attestations on by default since v1.11) -> GitHub release notes from towncrier.
- `SECURITY.md`: private reporting through GitHub security advisories, supported versions, proposed targets (acknowledge in 3 business days, triage in 7 days, critical fix in 30 days), credit policy.

## Acceptance tests
- `tests/security` green on `main` for every merged module.
- The raw-token scan fails on a fixture that stores one raw token on purpose; the fuzz test fails on a fixture endpoint that raises.
- Release dry run to TestPyPI shows attestations on the file page.
- O1 conformance result committed; each failure triaged in the file.
- Threat model covers all 7 flows; every mitigation links a test or an open request.

## Out of scope
Fixing findings in other modules (owners do it from request files), browser e2e (Q2), a paid external audit, F1's `ci.yml` and `pyproject.toml`.

## Notes
- Timing tests are noisy: dedicated job, retries, not a merge blocker until stable.
- Check the current OpenID conformance plans and the ASVS 5.0.x requirement ids before mapping.
