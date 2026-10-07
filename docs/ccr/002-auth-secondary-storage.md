# CCR: expose the secondary storage to plugins

- Requested by: P1
- Status: accepted 2026-10-07 (CONTRACT_VERSION 2)
- CONTRACTS section: 13, `GotAuthInstance`
- Affected work packages: C1 (implements it), F2 (testing kit), P1, O1 (caches), P2 (attempt counters)

## Change
Add a read-only property to `GotAuthInstance`:

```python
    secondary_storage: SecondaryStorage | None       # GotAuth(secondary_storage=...)
```

`GotAuth` returns the value it was constructed with. `make_context(secondary_storage=...)`
passes one to the fake.

## Why
P1's per-key rate limits must use `SecondaryStorage.incr` when one is configured, so the
limit holds across processes. Plugins can reach the instance only through `ctx.auth`, and
it had no way to return the storage.

## Compatibility
Additive. Code that does not use it is unaffected.

## Blocked work
None; P1 applies it in the same branch.
