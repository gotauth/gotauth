# Schema and migrations

GotAuth's tables live in your database, next to your own, with the prefix `auth_`:
`auth_user`, `auth_account`, `auth_session`, `auth_verification`, and one or more per
plugin (`auth_api_key`, `auth_passkey`, ...). Plugins can also add columns to
`auth_user` and `auth_session`.

<!-- sample: skip: a configuration fragment -->
```python
auth = GotAuth(..., advanced={"table_prefix": "auth_"})  # the default
```

Ids are strings such as `usr_01J...` (time-sortable), so your tables reference users
with a string column: `ForeignKey("auth_user.id")`.

## Two ways to create the tables

**`gotauth migrate`** creates missing tables and columns, and never drops or alters
anything. Good for development, prototypes and tests:

```bash
gotauth migrate --auth app.auth:auth             # --dry-run prints the SQL
```

**`gotauth generate`** writes an Alembic revision, for projects that manage their schema
with Alembic:

```bash
gotauth generate --auth app.auth:auth -m "gotauth tables"
alembic upgrade head
```

`--auth module:attr` names your `GotAuth` object (default `auth:auth`). `gotauth
generate --sql --dialect postgresql` prints the DDL instead.

## After adding a plugin

Run `gotauth generate` again for a revision with the plugin's tables and columns.

!!! warning "Check new NOT NULL columns"
    A plugin field with a default (for example `user.two_factor_enabled`) becomes a NOT
    NULL column. Added to a table that already has rows, it needs a `server_default`,
    or the upgrade fails. Until `gotauth generate` adds it for you
    ([#53](https://github.com/gotauth/gotauth/issues/53)), add it to the revision:

    ```python
    batch_op.add_column(
        sa.Column("two_factor_enabled", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    ```

## Without SQLAlchemy

`gotauth.storage.memory.memory_adapter()` keeps everything in memory, for tests. Other
storage implements the `Adapter` protocol and passes `adapter_conformance` from the
testing kit: see [Contracts](../modules/contracts.md).
