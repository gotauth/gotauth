## Work package

<!-- ID and brief, for example: C3, docs/plan/wp/C3-sessions.md -->

## What was built

## What was stubbed

<!-- Stubs and TODO(<WP-id>) notes, and which work package removes each one. -->

## Request and contract change files

<!-- docs/requests/<WP>-<topic>.md and docs/ccr/<WP>-<topic>.md added by this PR, or "none". -->

## Framework and spec differences

<!-- Where current docs differ from the brief, what you followed, and the versions you targeted. -->

## Skills used

<!-- The skills listed for this work package in docs/plan/README.md, or "none listed". -->

## Checklist (AGENTS.md section 4)

- [ ] Every acceptance test in the brief passes.
- [ ] `./dev.sh uv run poe check` is green (format check, lint, pyright strict, pytest).
- [ ] Public functions, classes and methods have Google-style docstrings; the module has a short `README.md` with a copy-paste example.
- [ ] A news fragment is in `changes/` (`<WP-id>.<type>.md`) if published code changed.
- [ ] No new runtime dependency unless the brief allows it; optional ones sit behind an extra and are imported lazily.
- [ ] Only files inside the write scope changed; commits follow Conventional Commits with a `Refs: <WP-id>` trailer.
- [ ] The branch is rebased on `main`.
