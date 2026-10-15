# CCR: sort ties break by id; the admin session cookie

- Requested by: P6 (code review of the admin plugin)
- Status: accepted 2026-10-15 (CONTRACT_VERSION 13)
- CONTRACTS sections: 3 (adapter rules), 7 (cookie names), 8 (purpose strings)
- Affected work packages: F2 (memory adapter, conformance suite), S1 (SQLAlchemy adapter), P6 (admin)

## Change
1. **Sort ties.** `find_many(..., sort_by=SortBy(field, direction))` orders rows with the same `field` value by `id`, in the same direction. Before, the order of ties was unspecified.
2. **Cookie.** New base name `admin_session`, owned by P6: the admin's own session token, signed, while the admin impersonates a user.
3. **Purpose string.** `"admin_session"` (P6) for that cookie.

## Why
`list_users` (P6) pages with `limit` and `offset` sorted by `created_at`. Users created in the same instant (imports, seeds, tests on a fake clock) tie, and SQL databases may return ties in any order on each query, so a page can repeat a user and skip another. Sorting by `id` instead is not an option: ids are opaque (section 1), and imported users keep theirs. A total order also makes every other paged listing stable.

The cookie and purpose string were named in the P6 brief but never added to the registries in sections 7 and 8.

## Compatibility
Additive. Orders that were unspecified are now fixed; no caller relied on them. The conformance suite checks the tie order.

## Blocked work
P6's `list_users` paging by `created_at`.
