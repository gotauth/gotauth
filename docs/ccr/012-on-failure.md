# CCR: work that outlasts a failed request

- Requested by: P2 (issue #39); P4 needs it too
- Status: accepted 2026-10-14 (CONTRACT_VERSION 12)
- CONTRACTS sections: 5 (`EndpointContext`)
- Affected work packages: C1 (implements), F2 (testing kit), P2 (email OTP attempts), P4 (magic link and email OTP attempts)

## Change
`EndpointContext.on_failure(work: Callable[[EndpointContext], Awaitable[None]]) -> None`.

When the request fails, its transaction rolls back. The core then:
- runs each `work`, in a transaction of its own, with a context bound to it
- runs them before the error goes to the client
- logs errors in `work` by type only, and still sends the original error

A request that succeeds drops its failure work. Work registered in a joined server call (`auth.api.call(..., ctx=ctx)`) belongs to the caller, as with `defer`. The testing kit's `call_endpoint` runs it the same way.

## Why
A wrong one-time code must count against an attempt limit (`verification.attempts`). Raising the error rolls the count back with everything else, so the limit is never reached. P2 had worked around it by answering with a 401 response instead of raising. Server-side callers then got a response object, not an `AuthError`, and `after` hooks treated the failure as a success.

## Compatibility
Additive. P2's `verify_two_factor_otp` raises `TWO_FACTOR_INVALID_CODE` again and counts with `on_failure`.

## Blocked work
P4's attempt limits.
