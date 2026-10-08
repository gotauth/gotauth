# CCR: auth_time on OAuth codes and grants

- Requested by: O1 (code review)
- Status: accepted 2026-10-08 (CONTRACT_VERSION 3)
- CONTRACTS section: 12.2, models `oauth_code` and `oauth_token`
- Affected work packages: O1, Q1 (conformance), O4 (token exchange keeps it)

## Change
Add an optional datetime field `auth_time` to `oauth_code` and `oauth_token`.

## Why
The OIDC ID token's `auth_time` is the time the user authenticated. O1 knows it at
authorize (the session's `created_at`), but the code and grant rows had nowhere to keep
it, so ID tokens carried the token issue time. A relying party that checks `max_age`
would then believe the user had just signed in.

## Compatibility
Additive and optional. No other package writes these models yet.

## Blocked work
None; O1 applies it in the same branch.
