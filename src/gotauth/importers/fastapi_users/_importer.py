"""Copy fastapi-users users and OAuth accounts into GotAuth (work package I1)."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from gotauth.contracts.adapter import Adapter, Where
from gotauth.contracts.errors import UniqueViolation

from ._mapping import (
    argon2_available,
    canonical_id,
    convert_hash,
    expires_at,
    hash_kind,
    normalize_email,
)

__all__ = ["ImportRefused", "ImportReport", "Problem", "import_fastapi_users"]

CREDENTIAL_PROVIDER = "credential"
USER_COLUMNS = (
    "id",
    "email",
    "hashed_password",
    "is_active",
    "is_superuser",
    "is_verified",
)
OAUTH_COLUMNS = (
    "id",
    "oauth_name",
    "access_token",
    "expires_at",
    "refresh_token",
    "account_id",
    "account_email",
    "user_id",
)
INACTIVE_REASON = "Inactive in fastapi-users"


class ImportRefused(Exception):
    """The import cannot start: a missing table or column, colliding table names, or
    no source database. Nothing was written."""


@dataclass(frozen=True)
class Problem:
    """Something the import could not carry over as it was.

    Attributes:
        kind: A stable name, e.g. ``"duplicate_email"`` or ``"unknown_hash"``.
        user_id: The source user id, when there is one.
        detail: What happened and what to do. Never a password hash or a token.
    """

    kind: str
    user_id: str | None
    detail: str


@dataclass
class ImportReport:
    """Counts and problems of one run. Holds no password hash and no token."""

    dry_run: bool
    source_users: int = 0
    users_imported: int = 0
    users_updated: int = 0
    users_existing: int = 0
    users_skipped: int = 0
    password_hashes: Counter[str] = field(default_factory=Counter[str])
    credential_accounts: int = 0
    passwords_updated: int = 0
    superusers: int = 0
    inactive: int = 0
    oauth_users_with_password: int = 0
    oauth_accounts: Counter[str] = field(default_factory=Counter[str])
    oauth_imported: int = 0
    oauth_updated: int = 0
    oauth_existing: int = 0
    oauth_skipped: int = 0
    tokens_stored: int = 0
    tokens_dropped: int = 0
    ignored_columns: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    problems: list[Problem] = field(default_factory=list[Problem])

    def problem(self, kind: str, user_id: str | None, detail: str) -> None:
        self.problems.append(Problem(kind, user_id, detail))

    def to_dict(self) -> dict[str, Any]:  # Any: JSON values
        """The report as JSON-ready data."""
        data = asdict(self)
        data["password_hashes"] = dict(self.password_hashes)
        data["oauth_accounts"] = dict(self.oauth_accounts)
        return data


@dataclass
class _Run:
    auth: Any  # Any: the app's GotAuth
    report: ImportReport
    update: bool
    has_admin: bool
    argon2_ok: bool
    now: datetime
    seen_emails: dict[str, str] = field(default_factory=dict[str, str])
    unknown_providers: set[str] = field(default_factory=set[str])


async def import_fastapi_users(
    auth: Any,  # Any: the app's GotAuth
    *,
    source_url: str | None = None,
    user_table: str = "user",
    oauth_table: str = "oauth_account",
    batch_size: int = 500,
    update: bool = False,
    dry_run: bool = False,
) -> ImportReport:
    """Copy users and OAuth accounts from a fastapi-users database into ``auth``.

    Users keep their ids (the UUID string), so the app's own tables still point at
    them, and their password hashes, so they sign in with their old passwords. Writes
    go through ``auth.database``, one transaction per batch, without database hooks or
    events. A user that is already there is skipped, so a second run adds nothing.

    Args:
        auth: The app's ``GotAuth``. Its tables must exist (``gotauth migrate``).
        source_url: The fastapi-users database. ``None`` reads the GotAuth database
            itself (same-database mode; needs the SQLAlchemy adapter).
        user_table: The fastapi-users user table.
        oauth_table: The fastapi-users OAuth account table; may be absent.
        batch_size: Users per read and per write transaction.
        update: Update users and accounts that are already there. A password GotAuth
            has changed since the import (a sign-in rehash, a reset) is never
            overwritten.
        dry_run: Count and check only; write nothing.

    Returns:
        The report.

    Raises:
        ImportRefused: Before anything is written, when the import cannot start.
    """
    if batch_size < 1:
        msg = "batch_size must be at least 1"
        raise ImportRefused(msg)
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

    target: Adapter = auth.database
    target_engine: AsyncEngine | None = getattr(target, "engine", None)
    same_database = source_url is None or (
        target_engine is not None
        and _url(source_url) == target_engine.url.render_as_string(hide_password=False)
    )
    if source_url is None:
        if target_engine is None:
            msg = "--source-url is needed: GotAuth does not use a SQLAlchemy database"
            raise ImportRefused(msg)
        engine = target_engine
    else:
        engine = create_async_engine(_url(source_url))
    try:
        if same_database:
            _check_collisions(target, (user_table, oauth_table))
        async with engine.connect() as conn:
            users, oauth = await conn.run_sync(_reflect, user_table, oauth_table)
        report = ImportReport(dry_run=dry_run)
        report.ignored_columns = {
            name: sorted(set(table.c.keys()) - set(known))
            for name, table, known in (
                (user_table, users, USER_COLUMNS),
                (oauth_table, oauth, OAUTH_COLUMNS),
            )
            if table is not None and set(table.c.keys()) - set(known)
        }
        try:
            await target.count("user")
        except Exception as exc:
            msg = "the GotAuth tables are missing: run `gotauth migrate` first"
            raise ImportRefused(msg) from exc
        run = _Run(
            auth=auth,
            report=report,
            update=update,
            has_admin="admin" in auth.plugin_ids,
            argon2_ok=argon2_available(),
            now=auth.clock.now(),
        )
        await _copy(run, engine, users, oauth, batch_size, dry_run)
        return report
    finally:
        if engine is not target_engine:
            await engine.dispose()


def _url(url: str) -> str:
    """The URL with an async driver: ``postgresql://`` uses asyncpg and ``sqlite://``
    aiosqlite, as GotAuth does."""
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    drivers = {
        "postgresql": "postgresql+asyncpg",
        "postgres": "postgresql+asyncpg",
        "postgresql+psycopg2": "postgresql+asyncpg",
        "sqlite": "sqlite+aiosqlite",
        "sqlite+pysqlite": "sqlite+aiosqlite",
    }
    driver = drivers.get(parsed.drivername, parsed.drivername)
    return parsed.set(drivername=driver).render_as_string(hide_password=False)


def _check_collisions(target: Adapter, names: Sequence[str]) -> None:
    tables = getattr(target, "tables", None)
    if tables is None:
        return
    taken = {table.name for table in tables().values()}
    clashes = sorted(set(names) & taken)
    if clashes:
        msg = (
            f"GotAuth's tables would use the fastapi-users table names {clashes}. "
            "Keep a table prefix (the default is advanced.table_prefix='auth_'), or "
            "import from another database with --source-url."
        )
        raise ImportRefused(msg)


def _reflect(
    conn: Any, user_table: str, oauth_table: str
) -> tuple[Any, Any]:  # Any: SQLAlchemy objects
    from sqlalchemy import MetaData, Table, inspect

    names = set(inspect(conn).get_table_names())
    if user_table not in names:
        msg = f"the source database has no {user_table!r} table"
        raise ImportRefused(msg)
    metadata = MetaData()
    users = Table(user_table, metadata, autoload_with=conn)
    missing = [name for name in USER_COLUMNS if name not in users.c]
    if missing:
        msg = f"the {user_table!r} table lacks the fastapi-users columns {missing}"
        raise ImportRefused(msg)
    oauth = None
    if oauth_table in names:
        oauth = Table(oauth_table, metadata, autoload_with=conn)
        missing = [name for name in OAUTH_COLUMNS if name not in oauth.c]
        if missing:
            msg = f"the {oauth_table!r} table lacks the fastapi-users columns {missing}"
            raise ImportRefused(msg)
    return users, oauth


async def _copy(
    run: _Run,
    engine: Any,  # Any: AsyncEngine
    users: Any,  # Any: Table
    oauth: Any,  # Any: Table | None
    batch_size: int,
    dry_run: bool,
) -> None:
    from sqlalchemy import select

    last: Any = None  # Any: the last source id read
    while True:
        query = select(users).order_by(users.c.id).limit(batch_size)
        if last is not None:
            query = query.where(users.c.id > last)
        # A short read per batch: SQLite allows one writer, and the writes follow.
        async with engine.connect() as conn:
            rows = [dict(row) for row in (await conn.execute(query)).mappings()]
            accounts: dict[Any, list[dict[str, Any]]] = defaultdict(list)
            if rows and oauth is not None:
                linked = select(oauth).where(
                    oauth.c.user_id.in_([row["id"] for row in rows])
                )
                for account in (await conn.execute(linked)).mappings():
                    accounts[account["user_id"]].append(dict(account))
        if not rows:
            return
        last = rows[-1]["id"]
        if dry_run:
            await _batch(run, run.auth.database, rows, accounts, write=False)
        else:
            async with run.auth.database.transaction() as tx:
                await _batch(run, tx, rows, accounts, write=True)


async def _batch(
    run: _Run,
    db: Adapter,
    rows: list[dict[str, Any]],
    accounts: Mapping[Any, list[dict[str, Any]]],
    *,
    write: bool,
) -> None:
    report = run.report
    for row in rows:
        report.source_users += 1
        linked = accounts.get(row["id"], [])
        user_id = await _user(run, db, row, write=write)
        if user_id is None:
            report.users_skipped += 1
            report.oauth_skipped += len(linked)
            for account in linked:
                report.oauth_accounts[str(account["oauth_name"])] += 1
            continue
        has_password = await _credential(run, db, user_id, row, write=write)
        if linked and has_password:
            report.oauth_users_with_password += 1
        for account in linked:
            await _oauth_account(run, db, user_id, row, account, write=write)


async def _user(
    run: _Run, db: Adapter, row: Mapping[str, Any], *, write: bool
) -> str | None:
    """Create or update the user; its GotAuth id, or None when it is skipped."""
    report = run.report
    user_id = canonical_id(row["id"])
    email = normalize_email(str(row["email"]))
    superuser = bool(row["is_superuser"])
    active = bool(row["is_active"])
    if superuser:
        report.superusers += 1
    if not active:
        report.inactive += 1
    first = run.seen_emails.get(email)
    if first is not None:
        report.problem(
            "duplicate_email",
            user_id,
            f"same email as {first} apart from case; skipped (merge them by hand)",
        )
        return None
    run.seen_emails[email] = user_id
    values: dict[str, Any] = {  # Any: field values
        "email": email,
        "email_verified": bool(row["is_verified"]),
    }
    if run.has_admin:
        values["role"] = "admin" if superuser else "user"
        values["banned"] = not active
        values["ban_reason"] = None if active else INACTIVE_REASON
    else:
        if superuser:
            report.problem(
                "superuser_not_admin",
                user_id,
                "superuser imported as an ordinary user: add the admin plugin to "
                "import superusers as admins",
            )
        if not active:
            report.problem(
                "inactive_skipped",
                user_id,
                "inactive user skipped: add the admin plugin to import inactive "
                "users as banned",
            )
            return None
    existing = await db.find_one("user", [Where("id", user_id)])
    if existing is not None:
        if existing["email"] != email:
            report.problem(
                "id_email_mismatch",
                user_id,
                "a GotAuth user has this id with another email; skipped",
            )
            return None
        if run.update:
            if write:
                await db.update(
                    "user",
                    [Where("id", user_id)],
                    {**values, "updated_at": run.now},
                )
            report.users_updated += 1
        else:
            report.users_existing += 1
        return user_id
    if await db.find_one("user", [Where("email", email)]) is not None:
        report.problem(
            "email_taken",
            user_id,
            "a GotAuth user with another id has this email; skipped",
        )
        return None
    if write:
        try:
            await db.create(
                "user",
                {
                    "id": user_id,
                    **values,
                    "name": None,
                    "image": None,
                    "created_at": run.now,
                    "updated_at": run.now,
                },
            )
        except UniqueViolation:
            report.problem(
                "email_taken", user_id, "the email was taken during the import"
            )
            return None
    report.users_imported += 1
    return user_id


async def _credential(
    run: _Run, db: Adapter, user_id: str, row: Mapping[str, Any], *, write: bool
) -> bool:
    """Carry the password hash over; whether the user has one GotAuth can verify."""
    report = run.report
    hashed = row["hashed_password"]
    kind = hash_kind(hashed if isinstance(hashed, str) else None)
    report.password_hashes[kind] += 1
    tagged = convert_hash(hashed) if isinstance(hashed, str) else None
    if kind == "unknown":
        report.problem(
            "unknown_hash",
            user_id,
            "password hash format GotAuth cannot verify; the user must reset the "
            "password or sign in another way",
        )
        return False
    if kind == "argon2id" and not run.argon2_ok:
        report.problem(
            "argon2_extra_missing",
            user_id,
            'argon2id hash not imported: install "gotauth[argon2]" and run again',
        )
        return False
    if tagged is None:  # a known kind always converts
        return False
    found = await db.find_one(
        "account",
        [Where("provider_id", CREDENTIAL_PROVIDER), Where("user_id", user_id)],
    )
    if found is None:
        if write:
            await db.create(
                "account",
                {
                    "id": run.auth.ids.new("acc"),
                    "user_id": user_id,
                    "provider_id": CREDENTIAL_PROVIDER,
                    "account_id": user_id,
                    "password_hash": tagged,
                    "created_at": run.now,
                    "updated_at": run.now,
                },
            )
        report.credential_accounts += 1
    elif run.update and _untouched(run, found) and found.get("password_hash") != tagged:
        if write:
            await db.update(
                "account",
                [Where("id", found["id"]), Where("updated_at", found["updated_at"])],
                {"password_hash": tagged},
            )
        report.passwords_updated += 1
    return True


def _untouched(run: _Run, account: Mapping[str, Any]) -> bool:
    """Whether a credential still holds the hash an import wrote: GotAuth moves
    ``updated_at`` on every change, and never writes bcrypt, nor argon2id unless
    it is the app's algorithm. Both must hold, so a GotAuth password is never lost."""
    stored = account.get("password_hash")
    tag = stored.partition("$")[0] if isinstance(stored, str) else ""
    own = run.auth.config.advanced.password_algorithm
    return (
        account["created_at"] == account["updated_at"]
        and tag in ("bcrypt", "argon2id")
        and tag != own
    )


async def _oauth_account(
    run: _Run,
    db: Adapter,
    user_id: str,
    row: Mapping[str, Any],
    account: Mapping[str, Any],
    *,
    write: bool,
) -> None:
    report = run.report
    provider_id = str(account["oauth_name"])
    account_id = str(account["account_id"])
    report.oauth_accounts[provider_id] += 1
    account_email = account.get("account_email")
    if isinstance(account_email, str) and normalize_email(
        account_email
    ) != normalize_email(str(row["email"])):
        report.problem(
            "account_email_differs",
            user_id,
            f"the {provider_id} account has another email than the user",
        )
    provider = run.auth.providers.get(provider_id)
    if provider is None and provider_id not in run.unknown_providers:
        run.unknown_providers.add(provider_id)
        report.problem(
            "unknown_provider",
            None,
            f"no social provider {provider_id!r} is configured; its accounts are "
            "imported, but sign-in with it needs the provider",
        )
    tokens: dict[str, Any] = {}  # Any: field values
    if provider is not None and provider.store_provider_tokens:
        crypto = run.auth.crypto
        access = account.get("access_token")
        refresh = account.get("refresh_token")
        tokens = {
            "access_token_enc": (
                crypto.encrypt(str(access), purpose="account_token")
                if access and write
                else None
            ),
            "refresh_token_enc": (
                crypto.encrypt(str(refresh), purpose="account_token")
                if refresh and write
                else None
            ),
            "access_token_expires_at": expires_at(account.get("expires_at")),
        }
        report.tokens_stored += 1
    elif account.get("access_token") or account.get("refresh_token"):
        report.tokens_dropped += 1
    found = await db.find_one(
        "account",
        [Where("provider_id", provider_id), Where("account_id", account_id)],
    )
    if found is not None:
        if found["user_id"] != user_id:
            report.problem(
                "account_owned_by_other_user",
                user_id,
                f"this {provider_id} account belongs to another GotAuth user; skipped",
            )
            report.oauth_skipped += 1
        elif run.update:
            if write and tokens:
                await db.update(
                    "account",
                    [Where("id", found["id"])],
                    {**tokens, "updated_at": run.now},
                )
            report.oauth_updated += 1
        else:
            report.oauth_existing += 1
        return
    if write:
        await db.create(
            "account",
            {
                "id": run.auth.ids.new("acc"),
                "user_id": user_id,
                "provider_id": provider_id,
                "account_id": account_id,
                **tokens,
                "created_at": run.now,
                "updated_at": run.now,
            },
        )
    report.oauth_imported += 1
