# CCR: an app hook for password rules

- Requested by: Q1 ([request](../requests/Q1-C2-asvs-gaps.md), items 2 and 3; issue #4)
- Status: accepted 2026-10-13 (CONTRACT_VERSION 8)
- CONTRACTS sections: 6 (error codes), 13 (`EmailPasswordConfig`)
- Affected work packages: C2 (calls it), D2 (shows the message), P4 and P6 (any later place that sets a password)

## Change
- `EmailPasswordConfig.password_check: Callable[[str, str], Awaitable[str | None]] | None = None`. It is called with `(password, email)` on sign-up, password reset and password change, after the length check.
  - Returning a message rejects the password with the new code `PASSWORD_REJECTED` (400), using that message.
  - Returning `None` accepts the password.
  - An exception fails the request with 500 (fail closed).
- **Order.** On sign-up the hook runs before the existing-email branch, so the answer is the same for every email. On reset it runs after the token is read, and a rejection rolls the transaction back, so the link still works. On change it runs after the current password is checked.

## Why
ASVS 6.2.4 (Level 1) asks for a check against common passwords, 6.2.12 for a check against breached passwords, and 6.1.2 and 6.2.11 for app-specific words. The maintainer chose a hook over a bundled list: GotAuth ships no third-party data and calls no external service by default, and each app picks its own source (a breached-password service, its own list). The C2 README shows a Have I Been Pwned example that sends only a 5-character hash prefix.

## Compatibility
Additive; the default `None` changes nothing.

## Blocked work
None.
