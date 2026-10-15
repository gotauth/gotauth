"""``gotauth import fastapi-users`` (work package I1)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ._importer import ImportRefused, ImportReport, import_fastapi_users

__all__ = ["main"]

_SHOWN_PROBLEMS = 20


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gotauth import",
        description="Copy users and OAuth accounts from fastapi-users into GotAuth.",
    )
    parser.add_argument("source", choices=["fastapi-users"], help="where from")
    parser.add_argument(
        "--auth", default="auth:auth", help="where your GotAuth is (module:attr)"
    )
    parser.add_argument(
        "--source-url",
        help="the fastapi-users database URL; the GotAuth database by default",
    )
    parser.add_argument("--user-table", default="user")
    parser.add_argument("--oauth-table", default="oauth_account")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument(
        "--update", action="store_true", help="update users already imported"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="count and check; write nothing"
    )
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``gotauth import fastapi-users ...``.

    Args:
        argv: Arguments after ``import``, starting with ``fastapi-users``; ``None``
            means ``sys.argv[1:]``.

    Returns:
        0 on success (problems are reported, not fatal), 1 when a batch failed, 2 when
        the import could not start.
    """
    try:
        args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    from gotauth.cli._commands import CliError, load_auth

    try:
        auth = load_auth(args.auth)
    except CliError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    try:
        report = asyncio.run(_run(auth, args))
    except ImportRefused as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except Exception as exc:
        # The type only: driver messages can carry row values.
        sys.stderr.write(
            f"error: the import stopped ({type(exc).__name__}). Batches before the "
            "failing one are committed; fix the cause and run again: users already "
            "imported are skipped.\n"
        )
        return 1
    sys.stdout.write(summary(report))
    if args.report is not None:
        args.report.write_text(json.dumps(report.to_dict(), indent=2) + "\n")
        sys.stdout.write(f"report written to {args.report}\n")
    return 0


async def _run(auth: Any, args: argparse.Namespace) -> ImportReport:  # Any: GotAuth
    try:
        return await import_fastapi_users(
            auth,
            source_url=args.source_url,
            user_table=args.user_table,
            oauth_table=args.oauth_table,
            batch_size=args.batch_size,
            update=args.update,
            dry_run=args.dry_run,
        )
    finally:
        engine = getattr(auth.database, "engine", None)
        if engine is not None:
            await engine.dispose()


def summary(report: ImportReport) -> str:
    """A short text summary of a report."""
    hashes = report.password_hashes
    providers = ", ".join(
        f"{name} {count}" for name, count in sorted(report.oauth_accounts.items())
    )
    lines = [
        "fastapi-users import"
        + (" (dry run: nothing written)" if report.dry_run else ""),
        f"users: {report.source_users} in the source, {report.users_imported} "
        f"imported, {report.users_updated} updated, {report.users_existing} "
        f"already there, {report.users_skipped} skipped",
        f"password hashes: {hashes['bcrypt']} bcrypt, {hashes['argon2id']} argon2id, "
        f"{hashes['unknown']} other (reset needed)",
        f"superusers: {report.superusers}; inactive: {report.inactive}; OAuth users "
        f"with a password hash: {report.oauth_users_with_password}",
        f"OAuth accounts: {sum(report.oauth_accounts.values())} in the source"
        + (f" ({providers})" if providers else "")
        + f", {report.oauth_imported} imported, {report.oauth_updated} updated, "
        f"{report.oauth_existing} already there, {report.oauth_skipped} skipped; "
        f"tokens stored for {report.tokens_stored}, dropped for "
        f"{report.tokens_dropped}",
    ]
    for table, columns in sorted(report.ignored_columns.items()):
        lines.append(f"ignored columns of {table}: {', '.join(columns)}")
    lines.append(f"problems: {len(report.problems)}")
    for problem in report.problems[:_SHOWN_PROBLEMS]:
        who = f" {problem.user_id}" if problem.user_id else ""
        lines.append(f"  {problem.kind}{who}: {problem.detail}")
    if len(report.problems) > _SHOWN_PROBLEMS:
        lines.append("  ... the full list is in the --report file")
    return "\n".join(lines) + "\n"
