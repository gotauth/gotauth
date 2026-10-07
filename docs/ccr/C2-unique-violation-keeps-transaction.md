# CCR: a UniqueViolation leaves the transaction usable

- Requested by: C2
- CONTRACTS section: 3, Adapter protocol (rules every adapter follows)
- Affected work packages: S1 (SQLAlchemy adapter), F2 (memory adapter and conformance suite), C2, C4, P5

## Change
Before:
- Unique violations (including `unique_together`) raise `UniqueViolation(model, fields)`.

After:
- Unique violations (including `unique_together`) raise `UniqueViolation(model, fields)`. The failed write has no effect and the surrounding transaction stays usable, so a caller can catch the error and carry on. SQL adapters run each write that can violate a constraint in a savepoint (`begin_nested()`).

The conformance suite gets a test: inside `transaction()`, create a row, trigger a `UniqueViolation`, catch it, create another row, commit, and find both rows.

## Why
C2 must answer a concurrent sign-up for the same email exactly like an existing email (9.1): catch the `UniqueViolation` from `create_user_record` and return `{"status": "verification_sent"}`. On Postgres, a failed statement aborts the whole transaction, so the commit after that reply would fail and the client would get a 500. That reveals the race and breaks the enumeration rule. C4 (account linking races) and P5 (duplicate invitations) catch the same error.

## Compatibility
The memory adapter already behaves this way. S1 has not merged, so nothing that exists breaks. S1 adds savepoints around creates and updates.

## Blocked work
None. C2 catches the error now; the memory adapter passes. The Postgres behaviour depends on S1 following this rule.
