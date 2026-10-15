"""``gotauth import fastapi-users`` (work package I1)."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import bcrypt
import pytest
from argon2 import PasswordHasher
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from gotauth.contracts.adapter import Where
from gotauth.importers.fastapi_users import (
    ImportRefused,
    ImportReport,
    _importer,
    import_fastapi_users,
    main,
)
from gotauth.importers.fastapi_users._mapping import (
    canonical_id,
    convert_hash,
    expires_at,
    hash_kind,
)
from gotauth.plugins.admin import admin
from gotauth.social import github
from gotauth.storage.memory import memory_adapter
from gotauth.storage.sqlalchemy import create_missing, sqlalchemy_adapter
from gotauth.testing import make_auth, make_client

# Ids in sort order: the importer reads by id, so the first of two case-only
# duplicates is DUP_1.
ADA = "0a000000-0000-4000-8000-000000000001"
BOB = "0b000000-0000-4000-8000-000000000002"
CY = "0c000000-0000-4000-8000-000000000003"
DUP_1 = "0d000000-0000-4000-8000-000000000004"
DUP_2 = "0d000000-0000-4000-8000-000000000005"
EVE = "0e000000-0000-4000-8000-000000000006"
OLI = "0f000000-0000-4000-8000-000000000007"
PASSWORDS = {ADA: "ada password 1", BOB: "bob password 1", CY: "cy password 1"}
ACCESS_TOKEN = "gho_access_token_value"
REFRESH_TOKEN = "ghr_refresh_token_value"
_argon2 = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def _bcrypt(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()


@dataclass
class Source:
    """The fixture fastapi-users data, and the hashes it holds."""

    hashes: dict[str, str]


async def make_source(engine: AsyncEngine) -> Source:
    """Create the fastapi-users tables (fastapi-users-db-sqlalchemy 7.0.0) with a
    ``nickname`` extra column and an app table that references users."""
    postgres = engine.dialect.name == "postgresql"
    guid = "UUID" if postgres else "CHAR(36)"
    hashes = {
        ADA: _bcrypt(PASSWORDS[ADA]),
        BOB: _argon2.hash(PASSWORDS[BOB]),
        CY: _bcrypt(PASSWORDS[CY]),
        DUP_1: _bcrypt("dup password 1"),
        DUP_2: _bcrypt("dup password 2"),
        EVE: "pbkdf2_sha256$600000$salt$hash",
        OLI: _argon2.hash("random unusable password"),
    }
    users = [
        # id, email, active, superuser, verified
        (ADA, "Ada@Example.com", True, True, True),
        (BOB, "bob@example.com", True, False, False),
        (CY, "cy@example.com", False, False, True),
        (DUP_1, "dup@example.com", True, False, True),
        (DUP_2, "DUP@example.com", True, False, True),
        (EVE, "eve@example.com", True, False, True),
        (OLI, "oli@example.com", True, False, True),
    ]
    async with engine.begin() as conn:
        await conn.execute(
            text(
                f'CREATE TABLE "user" (id {guid} NOT NULL PRIMARY KEY, '
                "email VARCHAR(320) NOT NULL, hashed_password VARCHAR(1024) NOT NULL, "
                "is_active BOOLEAN NOT NULL, is_superuser BOOLEAN NOT NULL, "
                "is_verified BOOLEAN NOT NULL, nickname VARCHAR(50))"
            )
        )
        await conn.execute(text('CREATE UNIQUE INDEX ix_user_email ON "user" (email)'))
        await conn.execute(
            text(
                f"CREATE TABLE oauth_account (id {guid} NOT NULL PRIMARY KEY, "
                "oauth_name VARCHAR(100) NOT NULL, "
                "access_token VARCHAR(1024) NOT NULL, "
                "expires_at INTEGER, refresh_token VARCHAR(1024), "
                "account_id VARCHAR(320) NOT NULL, "
                "account_email VARCHAR(320) NOT NULL, "
                f'user_id {guid} NOT NULL REFERENCES "user" (id) ON DELETE CASCADE)'
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE project (id INTEGER NOT NULL PRIMARY KEY, "
                f"name VARCHAR(50) NOT NULL, owner_id {guid} NOT NULL "
                'REFERENCES "user" (id))'
            )
        )
        for user_id, email, active, superuser, verified in users:
            await conn.execute(
                text(
                    'INSERT INTO "user" VALUES (:id, :email, :hash, :active, '
                    ":superuser, :verified, :nick)"
                ),
                {
                    "id": user_id,
                    "email": email,
                    "hash": hashes[user_id],
                    "active": active,
                    "superuser": superuser,
                    "verified": verified,
                    "nick": "nick",
                },
            )
        accounts = [
            (
                "1a000000-0000-4000-8000-000000000001",
                "github",
                "4242",
                "oli@example.com",
            ),
            (
                "1b000000-0000-4000-8000-000000000002",
                "google",
                "g-7",
                "o.l.i@gmail.com",
            ),
            (
                "1c000000-0000-4000-8000-000000000003",
                "github",
                "1717",
                "ada@example.com",
            ),
        ]
        owners = {"4242": OLI, "g-7": OLI, "1717": ADA}
        for account_id_, provider, account_id, account_email in accounts:
            await conn.execute(
                text(
                    "INSERT INTO oauth_account VALUES (:id, :name, :access, :exp, "
                    ":refresh, :account, :email, :user)"
                ),
                {
                    "id": account_id_,
                    "name": provider,
                    "access": ACCESS_TOKEN,
                    "exp": 1_900_000_000,
                    "refresh": REFRESH_TOKEN,
                    "account": account_id,
                    "email": account_email,
                    "user": owners[account_id],
                },
            )
        await conn.execute(
            text("INSERT INTO project VALUES (1, 'apollo', :owner)"), {"owner": ADA}
        )
    return Source(hashes=hashes)


@pytest.fixture
async def sqlite_engine(tmp_path: Path) -> AsyncGenerator[AsyncEngine]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'app.db'}")
    yield engine
    await engine.dispose()


def build(engine: AsyncEngine | None = None, **options: Any) -> Any:  # Any: GotAuth
    plugins = options.pop("plugins", [admin()])
    store = options.pop("store_provider_tokens", False)
    database = (
        sqlalchemy_adapter(engine) if engine is not None else options.pop("database")
    )
    return make_auth(
        database=database,
        plugins=plugins,
        social_providers=[
            github(client_id="id", client_secret="secret", store_provider_tokens=store)
        ],
        email_password={"require_email_verification": False},
        **options,
    )


async def ready(
    engine: AsyncEngine, **options: Any
) -> tuple[Any, Source]:  # Any: GotAuth
    source = await make_source(engine)
    auth = build(engine, **options)
    await create_missing(
        engine, auth.schema, table_prefix=auth.config.advanced.table_prefix
    )
    return auth, source


async def sign_in(
    auth: Any, email: str, password: str
) -> Any:  # Any: GotAuth, Response
    async with make_client(auth) as client:
        return await client.post(
            "/sign-in/email", json={"email": email, "password": password}
        )


async def credential(auth: Any, user_id: str) -> dict[str, Any]:  # Any: GotAuth
    row = await auth.database.find_one(
        "account", [Where("provider_id", "credential"), Where("user_id", user_id)]
    )
    assert row is not None
    return dict(row)


def check_counts(report: ImportReport) -> None:
    assert report.source_users == 7
    assert report.users_imported == 6
    assert report.users_skipped == 1
    assert dict(report.password_hashes) == {"bcrypt": 3, "argon2id": 2, "unknown": 1}
    assert report.credential_accounts == 5
    assert (report.superusers, report.inactive) == (1, 1)
    assert report.oauth_users_with_password == 2
    assert dict(report.oauth_accounts) == {"github": 2, "google": 1}
    assert report.oauth_imported == 3
    assert report.ignored_columns == {"user": ["nickname"]}
    kinds = sorted(problem.kind for problem in report.problems)
    assert kinds == [
        "account_email_differs",
        "duplicate_email",
        "unknown_hash",
        "unknown_provider",
    ]


# ---------------------------------------------------------------- mapping


def test_mapping_helpers() -> None:
    assert canonical_id("0A000000000040008000000000000001") == (
        "0a000000-0000-4000-8000-000000000001"
    )
    assert canonical_id(42) == "42"
    for prefix in ("$2a$", "$2b$", "$2y$"):
        hashed = prefix + "04$" + "a" * 53
        assert hash_kind(hashed) == "bcrypt"
        assert convert_hash(hashed) == "bcrypt$" + hashed
    argon = _argon2.hash("x")
    assert convert_hash(argon) == "argon2id$" + argon
    assert hash_kind(argon.replace("argon2id", "argon2i")) == "unknown"
    assert hash_kind("") == "unknown"
    assert convert_hash("md5$abc") is None
    assert expires_at(0) == datetime(1970, 1, 1, tzinfo=UTC)
    assert expires_at(None) is None
    assert expires_at("soon") is None


# ---------------------------------------------------------------- same database


@pytest.mark.parametrize("database", ["sqlite", "postgres"])
async def test_same_database_import(database: str, tmp_path: Path) -> None:
    from gotauth.testing import fresh_database_url

    databases = None
    if database == "sqlite":
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'app.db'}")
    else:
        base = os.environ.get("GOTAUTH_TEST_POSTGRES_URL")
        if not base:
            pytest.skip("GOTAUTH_TEST_POSTGRES_URL is not set")
        databases = cast(
            "AsyncGenerator[str, None]",
            fresh_database_url(
                base.replace("postgresql://", "postgresql+asyncpg://", 1)
            ),
        )
        engine = create_async_engine(await anext(databases))
    try:
        auth, source = await ready(engine)
        report = await import_fastapi_users(auth)
        check_counts(report)
        # GotAuth's tables sit next to the fastapi-users ones.
        async with engine.connect() as conn:
            names = set(
                await conn.run_sync(
                    lambda sync: (
                        __import__("sqlalchemy").inspect(sync).get_table_names()
                    )
                )
            )
        assert {"user", "oauth_account", "auth_user", "auth_account"} <= names
        # Ids are the source UUID strings, so the app's table still joins.
        async with engine.connect() as conn:
            joined = (
                await conn.execute(
                    text(
                        "SELECT auth_user.email FROM project JOIN auth_user "
                        "ON auth_user.id = CAST(project.owner_id AS VARCHAR(36))"
                    )
                )
            ).all()
        assert [row[0] for row in joined] == ["ada@example.com"]
        ada = await auth.database.find_one("user", [Where("id", ADA)])
        assert ada is not None
        assert (ada["role"], ada["email_verified"]) == ("admin", True)
        assert await auth.database.find_one("user", [Where("id", DUP_2)]) is None
        # Old passwords work, and move to the default scheme on that sign-in.
        assert (await credential(auth, ADA))["password_hash"].startswith("bcrypt$")
        for user_id, email in ((ADA, "ada@example.com"), (BOB, "bob@example.com")):
            response = await sign_in(auth, email, PASSWORDS[user_id])
            assert response.status_code == 200, response.text
            assert (await credential(auth, user_id))["password_hash"].startswith(
                "scrypt$"
            )
        banned = await sign_in(auth, "cy@example.com", PASSWORDS[CY])
        assert banned.json()["error"]["code"] == "ADMIN_USER_BANNED"
        again = await import_fastapi_users(auth)
        assert (again.users_imported, again.users_existing) == (0, 6)
        assert (again.oauth_imported, again.credential_accounts) == (0, 0)
        assert again.oauth_existing == 3
        assert source.hashes  # used by the fixture
    finally:
        await engine.dispose()
        if databases is not None:
            await databases.aclose()


async def test_dry_run_writes_nothing(sqlite_engine: AsyncEngine) -> None:
    auth, _ = await ready(sqlite_engine)
    report = await import_fastapi_users(auth, dry_run=True)
    assert report.dry_run
    check_counts(report)
    for model in ("user", "account"):
        assert await auth.database.count(model) == 0


async def test_small_batches_give_the_same_result(sqlite_engine: AsyncEngine) -> None:
    auth, _ = await ready(sqlite_engine)
    check_counts(await import_fastapi_users(auth, batch_size=2))


async def test_without_the_admin_plugin(sqlite_engine: AsyncEngine) -> None:
    auth, _ = await ready(sqlite_engine, plugins=[])
    report = await import_fastapi_users(auth)
    kinds = [problem.kind for problem in report.problems]
    assert "superuser_not_admin" in kinds
    assert "inactive_skipped" in kinds
    assert await auth.database.find_one("user", [Where("id", CY)]) is None
    ada = await auth.database.find_one("user", [Where("id", ADA)])
    assert ada is not None and "role" not in ada


@pytest.mark.parametrize("store", [False, True])
async def test_provider_tokens_only_when_stored(
    sqlite_engine: AsyncEngine, store: bool
) -> None:
    auth, _ = await ready(sqlite_engine, store_provider_tokens=store)
    report = await import_fastapi_users(auth)
    row = await auth.database.find_one(
        "account", [Where("provider_id", "github"), Where("account_id", "4242")]
    )
    assert row is not None and row["user_id"] == OLI
    if store:
        assert report.tokens_stored == 2
        sealed = row["access_token_enc"]
        assert sealed and ACCESS_TOKEN not in sealed
        assert auth.crypto.decrypt(sealed, purpose="account_token") == ACCESS_TOKEN
        assert (
            auth.crypto.decrypt(row["refresh_token_enc"], purpose="account_token")
            == REFRESH_TOKEN
        )
        assert row["access_token_expires_at"] == datetime.fromtimestamp(
            1_900_000_000, tz=UTC
        )
    else:
        assert report.tokens_dropped == 3
        assert row["access_token_enc"] is None
        assert row["refresh_token_enc"] is None
    google = await auth.database.find_one("account", [Where("provider_id", "google")])
    assert google is not None and google["access_token_enc"] is None


async def test_the_report_holds_no_hash_or_token(
    sqlite_engine: AsyncEngine, capsys: pytest.CaptureFixture[str]
) -> None:
    auth, source = await ready(sqlite_engine, store_provider_tokens=True)
    report = await import_fastapi_users(auth)
    from gotauth.importers.fastapi_users._cli import summary

    dumped = json.dumps(report.to_dict()) + summary(report) + capsys.readouterr().out
    for secret in (*source.hashes.values(), ACCESS_TOKEN, REFRESH_TOKEN):
        assert secret not in dumped
    assert "$2b$" not in dumped and "$argon2id$" not in dumped


async def test_argon2_hashes_need_the_extra(
    sqlite_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_importer, "argon2_available", lambda: False)
    auth, _ = await ready(sqlite_engine)
    report = await import_fastapi_users(auth)
    missing = [
        str(p.user_id) for p in report.problems if p.kind == "argon2_extra_missing"
    ]
    assert sorted(missing) == [BOB, OLI]
    found = await auth.database.find_one(
        "account", [Where("provider_id", "credential"), Where("user_id", BOB)]
    )
    assert found is None
    monkeypatch.undo()
    rerun = await import_fastapi_users(auth)
    assert rerun.credential_accounts == 2


async def test_update_keeps_passwords_gotauth_changed(
    sqlite_engine: AsyncEngine,
) -> None:
    auth, _ = await ready(sqlite_engine)
    await import_fastapi_users(auth)
    assert (await sign_in(auth, "ada@example.com", PASSWORDS[ADA])).status_code == 200
    async with sqlite_engine.begin() as conn:
        await conn.execute(
            text('UPDATE "user" SET is_verified = :yes, hashed_password = :hash'),
            {"yes": True, "hash": _bcrypt("new source password")},
        )
    plain = await import_fastapi_users(auth)
    assert plain.users_updated == 0
    updated = await import_fastapi_users(auth, update=True)
    assert updated.users_updated == 6
    bob = await auth.database.find_one("user", [Where("id", BOB)])
    assert bob is not None and bob["email_verified"] is True
    # Ada signed in on GotAuth (rehashed): her password stays.
    assert (await sign_in(auth, "ada@example.com", PASSWORDS[ADA])).status_code == 200
    # Cy's hash was never touched by GotAuth: it follows the source.
    assert updated.passwords_updated >= 1
    assert (await credential(auth, CY))["password_hash"].startswith("bcrypt$")


async def test_another_database_into_any_adapter(tmp_path: Path) -> None:
    source_url = f"sqlite:///{tmp_path / 'old.db'}"
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'old.db'}")
    try:
        await make_source(engine)
    finally:
        await engine.dispose()
    auth = build(database=memory_adapter())
    report = await import_fastapi_users(auth, source_url=source_url)
    check_counts(report)
    assert await auth.database.find_one("user", [Where("id", OLI)]) is not None


async def test_refusals(sqlite_engine: AsyncEngine, tmp_path: Path) -> None:
    auth = build(database=memory_adapter())
    with pytest.raises(ImportRefused, match="source-url"):
        await import_fastapi_users(auth)
    empty = f"sqlite:///{tmp_path / 'empty.db'}"
    with pytest.raises(ImportRefused, match="no 'user' table"):
        await import_fastapi_users(auth, source_url=empty)
    target, _ = await ready(sqlite_engine)
    with pytest.raises(ImportRefused):
        await import_fastapi_users(target, batch_size=0)
    unmigrated = build(sqlite_engine, advanced={"table_prefix": "new_"})
    with pytest.raises(ImportRefused, match="gotauth migrate"):
        await import_fastapi_users(unmigrated)


# ---------------------------------------------------------------- CLI

_APP = """
from gotauth.testing import make_auth
from gotauth.plugins.admin import admin
from gotauth.storage.sqlalchemy import sqlalchemy_adapter
from sqlalchemy.ext.asyncio import create_async_engine

engine = create_async_engine("sqlite+aiosqlite:///{path}")
auth = make_auth(
    database=sqlalchemy_adapter(engine),
    plugins=[admin()],
    advanced={{"table_prefix": "{prefix}"}},
)
"""


async def _cli_app(tmp_path: Path, prefix: str, module: str) -> None:
    db = tmp_path / f"{module}.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    try:
        await make_source(engine)
        if prefix:
            auth = build(engine, advanced={"table_prefix": prefix})
            await create_missing(engine, auth.schema, table_prefix=prefix)
    finally:
        await engine.dispose()
    (tmp_path / f"{module}.py").write_text(
        _APP.format(path=db.as_posix(), prefix=prefix)
    )


async def test_cli_imports_and_writes_the_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    await _cli_app(tmp_path, "auth_", "cli_app")
    monkeypatch.chdir(tmp_path)
    report = tmp_path / "report.json"
    code = await _in_thread(
        ["fastapi-users", "--auth", "cli_app:auth", "--report", str(report)]
    )
    out = capsys.readouterr().out
    assert code == 0, out
    assert "6 imported" in out
    data = json.loads(report.read_text())
    assert data["users_imported"] == 6
    assert data["password_hashes"] == {"bcrypt": 3, "argon2id": 2, "unknown": 1}


async def test_cli_refuses_colliding_table_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    await _cli_app(tmp_path, "", "clash_app")
    monkeypatch.chdir(tmp_path)
    code = await _in_thread(["fastapi-users", "--auth", "clash_app:auth"])
    assert code == 2
    assert "table prefix" in capsys.readouterr().err


async def test_cli_usage_errors(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["django-allauth"]) == 2
    assert await _in_thread(["fastapi-users", "--auth", "nowhere:auth"]) == 2
    assert "cannot import" in capsys.readouterr().err


async def _in_thread(argv: list[str]) -> int:
    """Run ``main`` (which calls ``asyncio.run``) off the test's event loop."""
    import asyncio

    return await asyncio.to_thread(main, argv)
