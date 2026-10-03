# B1: Better Auth interop

| | |
|---|---|
| Lane / wave | Interop / **Wave 4** (only on request) |
| Size | M |
| Depends on | C3, O1 |
| Can start | only after M3, a passed post-launch test, and public requests for it |
| Write scope | `src/gotauth/interop/better_auth/**` (the parent `interop/__init__.py` comes from F1), `tests/interop/better_auth/**`, `changes/B1.*.md` |
| Allowed new deps | none (PyJWT and httpx are core) |

## Goal
Let a FastAPI service share users with a Next.js app that runs Better Auth, without any feature-parity goal.

## Build
Build only the part the requests ask for; (a) first.
- (a) Verify Better Auth credentials from Python:
  - `better_auth_verifier(*, jwks_url, issuer, audience)`: verifies JWTs from Better Auth's JWT plugin against its JWKS (cached, refetched on an unknown `kid` with a rate limit, algorithm pinned to the JWKS key, never `none` or HS*). Returns its own `BetterAuthClaims` (`user_id` = `sub`, claims), not a 12.1 `Principal`: `via` has no value for foreign tokens, and the `eyJ` resolver prefix belongs to O1, so B1 never registers a `PrincipalResolver`.
  - Optional session check: forward the session cookie to Better Auth's get-session endpoint, with a short cache.
  - FastAPI dependency helper (lazy import), same style as A1 (`Annotated` alias defined in app code).
- (b) Read Better Auth's core tables (user, session, account, verification) for a one-way import into GotAuth, like I1: dry run, report, idempotent. Rows keep their Better Auth ids (opaque strings, section 1). GotAuth's `auth_` table prefix (section 0) lets both schemas share one database.
- Password hashes: the crypto kit verifies only the section 8 formats (`scrypt$`, `argon2id$`, `bcrypt$`). Better Auth's own scrypt format needs a new verify-only tag, which is a CCR to section 8 (F3 owns the kit), backed by test vectors. Without it, imported users reset their password.
- README: Next.js on Better Auth + FastAPI on GotAuth, step by step, with the pinned Better Auth version.

## Acceptance tests
- (a) Tokens signed in tests with the claim set from Better Auth's docs: valid accepted; wrong `iss`/`aud`, expired, `alg: none`, unknown `kid` rejected.
- (b) Fixture DB from Better Auth's documented schema imports; ids are preserved; dry run writes nothing; re-run adds nothing.

## Out of scope
Parity with Better Auth plugins, a JS client, tracking Better Auth releases.

## Notes
- Gate: start only with public evidence of demand (GitHub issues or discussions, inbound integration requests). Never chase Better Auth's release cadence: pin one documented version.
- Check Better Auth's current docs and source for the JWT plugin's algorithm, claims and JWKS path, and for its password hash format; record what you find.
