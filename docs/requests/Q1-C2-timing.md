# Q1: reset and verification replies are slower for real accounts

| | |
|---|---|
| From | Q1 (security tests) |
| For | the integrator (needs a CCR), then C2; later P4 and P5 follow the same pattern |
| Date | 2026-10-10 |
| Status | Applied 2026-10-12 as [CCR 007](../ccr/007-deferred-work.md) (issue #3); the timing tests pass without `xfail` |
| Found by | `tests/security/test_enumeration.py::test_timing_does_not_reveal_accounts` (`timing` marker) |

## What
`POST /request-password-reset` and `POST /send-verification-email` answer measurably slower when the email belongs to an account. Welch t-test over 200 interleaved runs per side, memory adapter, `base_url` off localhost so email goes out in the background:

| Endpoint | t | Mean gap |
|---|---|---|
| `/request-password-reset` | 10.99 | 323 us |
| `/send-verification-email` | 6.85 | 295 us |
| `/sign-in/email` (dummy hash for unknown emails) | below 4 | none found |

CONTRACTS section 9 defers only the *delivery* to a background task. For a known account the request still runs `issue_token` (a `delete` and a `create` on `verification`), the credential lookup and the template render inside the request transaction. The unknown path returns after the user lookup. On Postgres each extra statement is a network round trip, so the gap there is larger than on the memory adapter, and an attacker can average it out over repeated requests (CONTRACTS 9.1; ASVS 6.3.8, a Level 3 item).

## Why
Section 9.1 promises the same answer for known and unknown emails, and section 9 states that response time does not reveal whether an account exists. Only the body half of that holds today.

Until the fix lands, the two timing cases are marked `xfail(strict=True)`, so they turn into failures once the gap closes and the marks can be removed. The timing job is not a merge blocker (Q1 brief, notes).

## Proposed change
A CCR (next free number) adding deferred work to `EndpointContext`:

```python
def defer(self, work: Callable[[Adapter], Awaitable[None]]) -> None:
    """Run ``work`` after the request transaction commits, in its own
    transaction, on a tracked background task (``auth.drain()`` waits for it).
    On localhost it runs inline before the reply, like email delivery."""
```

Then in C2 (`src/gotauth/email_password/_plugin.py`), `_request_password_reset` and the resend branch of `_send_verification_email` look up the user and return; the credential check, `issue_token` and `_send` move into one deferred function. Errors in deferred work are logged without details, as `_send` does today.

The same rule then applies to P4 (magic link, email OTP) and P5 (invitations), which the 9.1 rules also bind.
