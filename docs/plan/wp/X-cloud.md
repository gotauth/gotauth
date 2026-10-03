# X: GotAuth Cloud (split into X1-X3)

| | |
|---|---|
| Lane / wave | Cloud / **Wave 5** |
| Size | XL: split into X1, X2, X3 before starting |
| Depends on | M3, post-launch test, `on_event` (section 14), P1, P5, P6, O1, O3 |
| Can start | only when production users ask for it publicly (Notes) |
| Write scope | `cloud/**` (separate deployable; never imported by the library) |
| Allowed new deps | none in the library; the service picks its own stack, recorded in `cloud/README.md` |

## Goal
An optional hosted service for teams running GotAuth in production: audit log, admin dashboard and billing. The library stays MIT and fully usable without it.

## Build
- **X1 events + audit log:** an exporter callable for `on_event` (batched, retried, bounded queue, drops on failure, never blocks a request; `on_event` already runs after commit through `auth.background`, and the exporter flushes on shutdown next to `auth.drain()`); ingestion API; audit log API (filter by user, type, date) with retention per plan, covering every section 14 type (incl. `user.banned`, `org.*`, `admin.impersonation_*`). Events carry no secrets (section 14).
- **X2 hosted admin dashboard:** users, sessions, orgs, API keys, agents, OAuth clients. Preferred design: actions go through the app's own GotAuth endpoints (P6, P5, P1, O1, O3) over a scoped connection, so user data stays in the customer's database; user removal uses P6 `remove_user`, which calls `delete_user` (13). Decide in X2.
- **X3 billing and team accounts:** Polar as merchant of record (checkout, subscriptions, webhooks); team accounts with roles. Prices to test: Free, Pro $29/mo, Team $99/mo.
- Later, each on request: abuse and bot detection, SSO connection management (on E1), email delivery.

## Acceptance tests
- The library test suite passes with no cloud code installed; nothing in `src/gotauth` imports `cloud`.
- Exporter: request latency unchanged when ingestion is down; no exported payload contains a token or password (scan).
- Audit log: tenant isolation (org A cannot read org B); retention deletes on schedule.
- Billing: Polar webhook signatures verified; replayed webhooks are idempotent.

## Out of scope
Moving any feature out of the MIT library; telemetry in the library or in `gotauth check`.

## Notes
- Gate: post-launch test passed and public requests from production users (issues, discussions, posts) for hosted features. Prices are hypotheses, not commitments.
- Check Polar's current API, fees and supported countries before X3.
- Publish a privacy policy and data-processing terms before accepting customer data.
