# CCR: change_email needs a fresh session

- Requested by: Q1 ([request](../requests/Q1-C2-asvs-gaps.md), item 1; issue #4)
- Status: accepted 2026-10-12 (CONTRACT_VERSION 5)
- CONTRACTS section: 13.1, core endpoint table
- Affected work packages: C2 (the endpoint), D2 (the client may need to send users back to sign-in)

## Change
- before: `| change_email | POST /change-email | session | StatusOut | C2 |`
- after: `| change_email | POST /change-email | session, fresh | StatusOut | C2 |`

A session older than `sessions.fresh_age` (1 day by default) gets `403 FRESH_SESSION_REQUIRED`, as `change_password`, `delete_user` and `unlink_account` already do.

## Why
ASVS 7.5.1 (Level 2) asks for re-authentication before changing attributes that affect authentication, such as the email address. Without it, a stolen session older than a day can start an email change. The confirmation link goes to the new address, which the thief controls, and the old address only gets a notice afterwards.

## Compatibility
Clients that call `change_email` with an old session now get `403 FRESH_SESSION_REQUIRED`. They should send the user to sign in again and then retry, as they already do for `change_password`.

## Blocked work
None.
