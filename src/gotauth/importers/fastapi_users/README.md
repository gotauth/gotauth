# gotauth.importers.fastapi_users

Moves a fastapi-users app to GotAuth (work package I1). Users keep their ids and
their passwords, so rows in the app's own tables still point at the right users,
and nobody has to reset a password.

Built against fastapi-users 15.0.5 and fastapi-users-db-sqlalchemy 7.0.0 (pwdlib
0.3.0 hashes), the default `user` and `oauth_account` tables.

## Steps

1. **Set up GotAuth beside fastapi-users** in the same database. GotAuth's tables
   carry `advanced.table_prefix` (`auth_` by default), so `auth_user` sits next to
   fastapi-users' `user`. Then create the tables:

   ```bash
   gotauth migrate --auth app.auth:auth
   ```

   Install the extras for the hashes your users have: `gotauth[bcrypt]` for bcrypt
   and `gotauth[argon2]` for argon2id (pwdlib's default).

2. **Dry run** and read the problems:

   ```bash
   gotauth import fastapi-users --auth app.auth:auth --dry-run --report dry-run.json
   ```

3. **Import:**

   ```bash
   gotauth import fastapi-users --auth app.auth:auth --report import.json
   ```

   A second run adds nothing: users and accounts already there are skipped. Until
   you switch over, `--update` copies changes made in fastapi-users meanwhile (see
   below).

4. **Switch the app over** (API mapping below), and repoint your foreign keys.
5. **Drop the old tables** once you are sure: `oauth_account`, then `user`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--auth` | `auth:auth` | Your `GotAuth` instance, `module:attr` |
| `--source-url` | the GotAuth database | The fastapi-users database. `postgresql://` and `sqlite://` URLs get the async drivers |
| `--user-table` | `user` | |
| `--oauth-table` | `oauth_account` | May be absent |
| `--batch-size` | `500` | Users per read and per write transaction |
| `--update` | off | Update users and accounts already imported |
| `--dry-run` | off | Count and check; write nothing |
| `--report PATH` | | Write the JSON report |

From Python: `await import_fastapi_users(auth, dry_run=True)` returns the same
report. Exit codes: 0 done (problems are reported, not fatal), 1 a batch failed
(earlier batches are committed; run again) or the report could not be written, 2
the import could not start. Each batch reads what GotAuth already holds with one
query per model.

## What is copied

| fastapi-users | GotAuth |
|---|---|
| `user.id` (UUID) | `user.id`, the canonical UUID string (`0a1b...-...`) |
| `user.email` | lower-cased. Emails that differ only in case: the first by id is kept, the others are skipped and reported |
| `user.is_verified` | `email_verified` |
| `user.hashed_password` | a `credential` account: bcrypt (`$2a$`, `$2b$`, `$2y$`) as `bcrypt$...`, argon2id as `argon2id$...`. Other formats get no password and are reported: those users reset it or sign in another way |
| `user.is_superuser` | `role="admin"`, with the [admin plugin](../../plugins/admin/README.md); without it, reported |
| `user.is_active=False` | `banned=True` with the admin plugin; without it, the user is skipped and reported |
| `oauth_account` | an `account` with `provider_id=oauth_name` and the same `account_id` |
| `access_token`, `refresh_token`, `expires_at` | encrypted (purpose `"account_token"`) only when that provider has `store_provider_tokens=True`; else dropped |

`created_at` and `updated_at` are the import time. Extra columns (for example a
`nickname` you added) are not copied; the report lists them. Writes go through the
GotAuth adapter without database hooks or events.

On the first sign-in, GotAuth checks the old hash and stores a new one with its own
algorithm (scrypt by default).

**Users created by fastapi-users OAuth sign-in** have a hash of a random password
nobody knows. They are imported as they are and counted in the report ("OAuth users
with a password hash").

**`--update`** copies the user fields (email verified, role, ban) and provider
tokens again, but only what GotAuth has not changed since:
- a user row changed in GotAuth (a ban, a role, a verified email) is kept and
  reported as `changed_in_gotauth`;
- a password is kept once the user has signed in to GotAuth (which rehashes) or
  changed it.

A user whose GotAuth id holds another email is reported and left alone.

## Problems in the report

| Kind | Meaning |
|---|---|
| `duplicate_email` | Same email as another user apart from case; skipped |
| `email_taken` | A GotAuth user with another id has this email; skipped |
| `id_email_mismatch` | A GotAuth user has this id with another email; skipped |
| `unknown_hash` | Password hash format GotAuth cannot verify |
| `bcrypt_extra_missing` | bcrypt hash not imported; install `gotauth[bcrypt]` and run again |
| `argon2_extra_missing` | argon2id hash not imported; install `gotauth[argon2]` and run again |
| `superuser_not_admin` | Imported as an ordinary user (no admin plugin) |
| `inactive_skipped` | Skipped (no admin plugin to ban it) |
| `inactive_already_imported` | Deactivated after an earlier import and still active in GotAuth (no admin plugin) |
| `changed_in_gotauth` | `--update` kept the GotAuth user fields |
| `account_email_differs` | The OAuth account's email is not the user's |
| `unknown_provider` | No social provider with this name; the accounts are imported anyway |
| `account_owned_by_other_user` | The OAuth account belongs to another GotAuth user; skipped |

The report and the output never contain a password hash or a token.

## Foreign keys

Ids keep their values, so `project.owner_id` still matches `auth_user.id`. The
constraint itself still points at `user`. Repoint it with an Alembic migration
before dropping the old tables. On Postgres the column is `UUID` and GotAuth's ids
are strings, so cast it too:

```python
def upgrade() -> None:
    op.drop_constraint("project_owner_id_fkey", "project", type_="foreignkey")
    op.alter_column(
        "project", "owner_id",
        type_=sa.String(36), postgresql_using="owner_id::text",
    )
    op.create_foreign_key(
        "project_owner_id_fkey", "project", "auth_user",
        ["owner_id"], ["id"], ondelete="CASCADE",
    )
```

On SQLite the ids are already `CHAR(36)` strings; use `op.batch_alter_table` to
recreate the constraint.

## API mapping

| fastapi-users | GotAuth |
|---|---|
| `fastapi_users.current_user(active=True)` | `CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]` |
| `current_user(optional=True)` | `Depends(auth.fastapi.optional_user)` |
| `current_user(active=True, verified=True)` | `email_password={"require_email_verification": True}`; unverified users cannot sign in |
| `current_user(superuser=True)` | the admin plugin: check `user.role == "admin"` |
| `get_auth_router(backend)` | `app.include_router(auth.fastapi.router(), prefix="/api/auth")` |
| `get_register_router`, `get_verify_router`, `get_reset_password_router` | in the same router: `/sign-up/email`, `/verify-email`, `/request-password-reset`, `/reset-password` |
| `get_users_router` | `GET /session`, `PATCH /user`, `DELETE /user`; admin endpoints under `/admin/users` |
| `get_oauth_router(client, ...)` | `GotAuth(social_providers=[github(...), google(...)])`, `/sign-in/social` |
| `UserManager.on_after_register` and friends | `GotAuth(on_event=...)` (`user.created`, `password.reset`, ...) |
| JWT or database strategy | hashed database sessions in an HttpOnly cookie, or `Bearer gas_...` |
