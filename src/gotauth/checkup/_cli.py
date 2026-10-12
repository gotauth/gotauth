"""Command line interface of ``gotauth check``."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from gotauth import __version__
from gotauth.checkup._output import format_json, format_sarif, format_text
from gotauth.checkup._rules import resolve_rule_ids
from gotauth.checkup._scan import scan

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_FAIL_UNDER = 1
EXIT_USAGE = 2


def _score_argument(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        number = -1
    if not 0 <= number <= 100:
        msg = f"expected a whole number from 0 to 100, got {value!r}"
        raise argparse.ArgumentTypeError(msg)
    return number


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser of ``gotauth check``."""
    parser = argparse.ArgumentParser(
        prog="gotauth check",
        description=(
            "Find risky hand-written auth code in a Python project and print a score "
            "from 0 to 100. Files are only read and parsed: nothing is imported, run "
            "or sent anywhere."
        ),
        epilog=(
            "Silence one finding with a comment on its line: # gotauth: ignore[GA006]. "
            "Exit codes: 0 done, 1 score below --fail-under, 2 usage error. "
            "Rules: https://gotauth.ablacky.com/check"
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="files or folders to scan (default: the current folder)",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--json", action="store_true", help="print JSON instead of text"
    )
    output.add_argument(
        "--sarif",
        action="store_true",
        help="print SARIF 2.1.0 for GitHub code scanning instead of text",
    )
    parser.add_argument(
        "--fail-under",
        type=_score_argument,
        metavar="N",
        help="exit with code 1 when the score is below N (0 to 100)",
    )
    parser.add_argument(
        "--select",
        action="append",
        default=[],
        metavar="IDS",
        help="run only these rules, comma-separated (for example GA001,GA003)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="IDS",
        help="leave out these rules, comma-separated",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help=(
            "leave out files and folders that match GLOB (for example 'tests' or "
            "'*_test.py'); can be repeated"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def _write(text: str) -> None:
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        # A console that cannot show a file name: escape what it cannot encode.
        encoding = sys.stdout.encoding or "ascii"
        sys.stdout.write(text.encode(encoding, "backslashreplace").decode(encoding))
    sys.stdout.flush()


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``gotauth check``.

    Args:
        argv: Arguments without the program name. ``None`` means ``sys.argv[1:]``.

    Returns:
        The exit code: 0 when done, 1 when the score is below ``--fail-under``, 2 on
        a usage error (unknown option or rule id, missing path).
    """
    parser = build_parser()
    try:
        args = parser.parse_args(None if argv is None else list(argv))
        paths: list[str] = args.paths or ["."]
        select: list[str] = args.select
        ignore: list[str] = args.ignore
        exclude: list[str] = args.exclude
        try:
            resolve_rule_ids(select, ignore)
        except ValueError as error:
            parser.error(str(error))
        for path in paths:
            if not os.path.exists(path):
                parser.error(f"no such file or folder: {path}")
    except SystemExit as exit_request:
        code = exit_request.code
        return (
            code if isinstance(code, int) else (EXIT_OK if code is None else EXIT_USAGE)
        )

    report = scan(paths, select=select, ignore=ignore, exclude=exclude)
    if args.json:
        _write(format_json(report))
    elif args.sarif:
        _write(format_sarif(report))
    else:
        _write(format_text(report))
    fail_under: int | None = args.fail_under
    if fail_under is not None and report.score < fail_under:
        return EXIT_FAIL_UNDER
    return EXIT_OK
