# CCR: deferred work after the commit

- Requested by: Q1 ([request](../requests/Q1-C2-timing.md), issue #3)
- Status: accepted 2026-10-12 (CONTRACT_VERSION 7)
- CONTRACTS sections: 5 (`EndpointContext`), 9 (email and account enumeration)
- Affected work packages: C1 (runs the work), C2 (uses it), F2 (`FakeContext`), P4 and P5 (magic links, OTPs and invitations follow the same rule)

## Change
`EndpointContext` gains:

```python
def defer(self, work: Callable[[EndpointContext], Awaitable[None]]) -> None: ...
```

`work` runs after the request's transaction commits, in a transaction of its own, and gets a context bound to that transaction.
- Off localhost it runs on a background task, as email delivery does, so the reply does not wait. `auth.drain()` waits for it.
- On localhost it runs before the reply, so console email links still appear before the page reloads.
- Its events are delivered after its own commit.
- Errors are logged by exception type only and never reach the client.
- A request that rolls back drops its deferred work.
- Nested server calls (`auth.api.call(..., ctx=ctx)`) add to the outer request's queue.

`FakeContext.defer` queues the work, and `call_endpoint` runs it inline right after the commit, so unit tests see its effects at once. `FakeContext.run_deferred()` runs the queue by hand.

## Why
Section 9 moved email delivery to the background so response time would not reveal accounts. But `request_password_reset` and `send_verification_email` still wrote the token row, and checked the credential, inside the request for existing accounts only. The Q1 timing tests measured about 300 us of difference on the memory adapter (t = 10.99 and 6.85 over 200 runs), and on Postgres each statement is a network round trip.

## Compatibility
Additive for handlers. Code that implements `EndpointContext` itself must add `defer`.

## Blocked work
None. C2 applies it in the same change.
