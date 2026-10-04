# Contract change requests

The shared interfaces in `docs/plan/CONTRACTS.md` and `src/gotauth/contracts/` are frozen at milestone M0. After M0, nobody edits them directly. To change a contract, write a contract change request (CCR) here and stop the work that depends on it until the integrator decides (AGENTS.md section 1).

## File name

Agents name a CCR `<WP-id>-<topic>.md`, for example `P5-org-role-event.md`. Using your own work-package ID means parallel agents never pick the same name.

When the integrator accepts a CCR, they rename it to `<NNN>-<topic>.md` with the next free three-digit number (`001-org-role-event.md`), update CONTRACTS.md and the contracts code, and bump `CONTRACT_VERSION`. Rejected CCRs are deleted, with the reason given in the pull request.

## Content

```markdown
# CCR: <short title>

- Requested by: <WP-id>
- CONTRACTS section: <number and name>
- Affected work packages: <IDs that implement or call this contract>

## Change
The exact new or changed names, signatures, fields, error codes, events, cookie names or
purpose strings. Show before and after.

## Why
What cannot be built correctly with the current contract.

## Compatibility
What breaks for code that already uses the contract, and how it migrates.

## Blocked work
What you stopped while waiting for the decision.
```
