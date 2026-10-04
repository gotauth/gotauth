# Requests

A request asks another work package's owner, or the integrator, for a change outside your write scope: a dependency in `pyproject.toml`, a fix in someone else's module, a CI step. You do not make that change yourself (AGENTS.md section 1); you file a request and continue with a local stub or the testing kit.

Contract changes (anything in `docs/plan/CONTRACTS.md` or `src/gotauth/contracts/`) are not requests; they go to [`docs/ccr/`](../ccr/README.md).

## File name

`<WP-id>-<topic>.md`, for example `S2-extras.md` or `C2-session-revoke-hook.md`. Use your own work-package ID, so parallel agents never pick the same name.

## Content

```markdown
# <WP-id>: <short title>

## What
The change you need, and in which file or module. Name the owner work package.

## Why
What it unblocks or fixes, and what you do in the meantime (stub, skipped test, TODO note).

## Proposed diff
A unified diff or an exact description of the edit.
```

## What happens next

The integrator reads new requests after each merge and accepts, rejects or schedules them, then tells the owner. An accepted request is applied by the owner of the file, never by the requester.
