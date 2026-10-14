# CCR: user delete hooks always get a context

- Requested by: O3 (issue #36)
- Status: accepted 2026-10-14 (CONTRACT_VERSION 11)
- CONTRACTS sections: 13 (`delete_user`)
- Affected work packages: C1 (implements), O3 (its user `before_delete` hook), P5 and P6 (later user delete hooks)

## Change
`auth.delete_user(None, user_id)` creates a server context, then:
- runs the delete and its hooks in one transaction, through the hooked adapter
- publishes the events after the commit, including `user.deleted`, which this path did not emit before
- runs any deferred work

So a user `before_delete` or `after_delete` hook gets that context, never `None`, on this path. `delete_user(ctx, user_id)` is unchanged.

## Why
O3 must revoke and delete a user's agents, with their keys and tokens, in the same transaction as the user. A hook with `ctx=None` can neither call another plugin with `auth.api.call(..., ctx=ctx)` nor use the delete's transaction. A second transaction would deadlock on the memory adapter and wait on SQLite's lock.

## Compatibility
- Hooks that handled `ctx=None` keep working; they now get a context.
- Listeners now receive `user.deleted` for server deletes too.

## Blocked work
O3's user delete hook.
