# CCR: absolute session lifetime, and sign-in ends the presented session

- Requested by: Q1 ([request](../requests/Q1-C3-asvs-gaps.md), issue #5)
- Status: accepted 2026-10-12 (CONTRACT_VERSION 6)
- CONTRACTS section: 7, sessions (`SessionConfig`, re-authentication)
- Affected work packages: C3 (session service), C1 (`complete_sign_in`, `finish_challenge`), P2 (second-factor sign-in goes through `finish_challenge`)

## Change
1. `SessionConfig` gains `absolute_lifetime: Duration | None = "30d"`. Creating a session caps its lifetime at this. A sliding refresh never sets `expires_at` past `created_at + absolute_lifetime`, and never moves it backwards. `None` turns the cap off.
2. `complete_sign_in` and `finish_challenge` look up the session behind the request's session cookie by token hash, without a sliding refresh and without writing a cookie. Once the new session exists, they revoke that session if it is a different one, which emits `session.revoked`. Bearer tokens are not touched.

## Why
- ASVS 7.3.2 (Level 2): before, sessions slid forever, so a session used at least weekly never ended and a stolen token worked for as long as the thief kept using it.
- ASVS 7.2.4 (Level 1): re-authentication must end the current session token. A valid session cookie sent with a sign-in request kept working after the new session was issued.

## Compatibility
- Sessions older than 30 days end at their next check after the upgrade, so long-lived sessions sign in again once. Apps that want the old behavior set `sessions={"absolute_lifetime": None}`.
- Signing in from a browser that is already signed in now ends the previous session. Other devices' sessions are unaffected.

## Blocked work
None.
