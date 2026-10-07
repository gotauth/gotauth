"""The ``gotauth`` command line interface (work package S1).

Importing this module loads no optional extras, so ``uvx gotauth check`` works with a
bare install.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

__all__ = ["main"]

_DELEGATED = ("check", "import")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gotauth", description="GotAuth: auth for Python AI backends."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="write auth.py and a secret in .env")
    init.add_argument("--dir", default=".", help="project directory (default: .)")
    init.add_argument(
        "--database-url",
        default="sqlite+aiosqlite:///auth.db",
        help="DATABASE_URL fallback written into auth.py",
    )
    init.add_argument(
        "--force", action="store_true", help="replace an existing auth.py"
    )

    for name, help_text in [
        ("generate", "write an Alembic revision, or print SQL with --sql"),
        ("migrate", "create missing tables and columns (never drops or alters)"),
    ]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument(
            "--auth", default="auth:auth", help="where your GotAuth is (module:attr)"
        )
        if name == "generate":
            command.add_argument("--sql", action="store_true", help="print DDL instead")
            command.add_argument(
                "--dialect", choices=("postgresql", "sqlite"), default="postgresql"
            )
            command.add_argument("-m", "--message", default="gotauth schema")
            command.add_argument("--config", default="alembic.ini")
        else:
            command.add_argument(
                "--dry-run", action="store_true", help="only print SQL"
            )

    commands.add_parser("secret", help="print a new secret")
    commands.add_parser(
        "check", help="scan a project for risky auth code", add_help=False
    )
    commands.add_parser(
        "import", help="import users from another library", add_help=False
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ``gotauth`` command.

    Args:
        argv: Arguments without the program name; ``None`` means ``sys.argv[1:]``.

    Returns:
        The exit code.
    """
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list and args_list[0] in _DELEGATED:
        from gotauth.cli._commands import delegate

        return delegate(args_list[0], args_list[1:])
    args = _parser().parse_args(args_list)
    from gotauth.cli import _commands

    handlers = {
        "init": _commands.cmd_init,
        "generate": _commands.cmd_generate,
        "migrate": _commands.cmd_migrate,
        "secret": _commands.cmd_secret,
    }
    try:
        return handlers[args.command](args)
    except _commands.CliError as error:
        sys.stderr.write(f"gotauth: {error}\n")
        return 1
