# I1: `gotauth import fastapi-users`

| | |
|---|---|
| Lane / wave | Migration / **Wave 3** (parallel) |
| Size | M |
| Depends on | S1, F3 |
| Can start | after M2; mapping logic earlier against the memory adapter |
| Write scope | `src/gotauth/importers/fastapi_users/**` (incl. `README.md`), `tests/importers/fastapi_users/**`, `changes/I1.*.md` |
| Allowed new deps | none (uses the `sqlalchemy` extra; tests use the `bcrypt`, `argon2` and `sqlite` extras) |

## Goal
Move a fastapi-users app to GotAuth with one command: users log in with their old passwords, and rows in the app's own tables still point at the right users.

## Build
- `main(argv) -> int`; S1 wires `gotauth import fastapi-users` with a lazy import.
- Options: `--auth module:attr` (the app's `GotAuth` instance), `--source-url` (fastapi-users DB; may equal the target), `--user-table user`, `--oauth-table oauth_account`, `--batch-size 500`, `--update`, `--dry-run`, `--report PATH` (JSON).
- Source: the default fastapi-users SQLAlchemy schema, read with SQLAlchemy Core reflection. `user`: `id` (UUID), `email`, `hashed_password`, `is_active`, `is_superuser`, `is_verified`. `oauth_account`: `id`, `oauth_name`, `access_token`, `expires_at`, `refresh_token`, `account_id`, `account_email`, `user_id`. Extra columns are ignored and listed.
- Mapping:
  - `id` -> GotAuth user id as the canonical UUID string, so the app's foreign key values still match. Section 1 allows imported rows to keep their ids; GotAuth treats ids as opaque strings.
  - `email` lower-cased; case-only duplicates -> problem, second row skipped. `is_verified` -> `email_verified`. `created_at`/`updated_at` = import time.
  - `hashed_password` -> `credential` account (`account_id` = user id): `$2a$`/`$2b$` (`$2y$` if F3 verifies it) -> `bcrypt$<hash>`; `$argon2id$` (pwdlib, passlib) -> `argon2id$<PHC>` (needs the `argon2` extra, else reported). Other formats -> no credential account, reported (reset needed). C2 rehashes on the next login (`needs_rehash`).
  - `is_superuser` -> `role="admin"` and `is_active=False` -> `banned=True`. These fields come from the admin plugin (P6, 2.1): only when `"admin"` is in `auth.plugin_ids`; else superusers are reported and inactive users skipped and reported.
  - `oauth_account` -> `account` (`provider_id` = `oauth_name`, `account_id`, `access_token_expires_at` from epoch `expires_at`). Tokens are encrypted with purpose `"account_token"` (shared with C4, section 8) only when the matching provider has `store_provider_tokens=True`, else dropped. `account_email` differing from the user email -> reported.
- Writes go through the instance's adapter, one transaction per batch, without `DatabaseHooks` or events.
- Idempotent: an existing user with the same id is skipped (updated with `--update`); accounts dedupe on (`provider_id`, `account_id`); same id with another email -> problem.
- `--dry-run`: counts (users, hash types, OAuth accounts per provider, skipped) and problems; no writes.
- Same-database mode: GotAuth tables carry `advanced.table_prefix` (default `"auth_"`, so `auth_user`), which does not clash with fastapi-users' `user`. Only if the resolved GotAuth table names collide with the source tables (e.g. `table_prefix=""`) -> refuse (exit 2) and explain how to set a prefix.
- `README.md` (draft for G2's guide): steps, dry run first, the FK note (values match; repointing FK constraints from `user` to `auth_user`, and UUID -> varchar on Postgres, is an Alembic migration the guide shows), dropping the old tables afterwards, API mapping (`current_active_user` -> `CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]`, ...).

## Acceptance tests
- Fixture SQLite DB with the fastapi-users DDL: bcrypt and argon2id hashes, verified and unverified, superuser, inactive, OAuth accounts, a case-duplicate email, an unknown hash format.
- Same-database run with default settings: GotAuth's `auth_*` tables sit next to `user` and `oauth_account`, nothing collides.
- `sign_in_email` with the original passwords works for bcrypt and argon2 users; `password_hash` moves to the default scheme after that login.
- User ids equal the source UUID strings; a fixture app table referencing users still joins.
- `--dry-run` changes no row and its report matches expected counts; a second real run adds nothing.
- With and without P6: `role`/`banned` set vs reported.
- Provider tokens absent unless `store_provider_tokens`; when present, encrypted and decryptable with purpose `"account_token"`.
- No password hash or token in the report or logs. `table_prefix=""` with colliding names -> exit code 2.

## Out of scope
The CLI entry point (S1), the published migration guide (G2), password hashing itself (F3, C2).

## Notes
- Check the current fastapi-users and fastapi-users-db-sqlalchemy source for column names and types before coding; record the versions in the README.
- Users created by fastapi-users OAuth flows have a random, unusable password hash. Import it as is and count these users in the report.
