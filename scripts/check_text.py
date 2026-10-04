"""Fail on en dashes, em dashes and emoji in project text files.

Usage::

    python scripts/check_text.py [PATH ...]

Without arguments it checks ``src``, ``tests``, ``docs`` and the Markdown files in the
repository root. AGENT-RULES section 5 asks for plain ASCII punctuation and no emoji.
Tests that need such characters as data use escapes, for example ``"\\u2014"``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATHS: tuple[str, ...] = ("src", "tests", "docs", "*.md")
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site",
    }
)
# Verbatim third-party snapshots kept as research evidence (work package R1).
SKIP_PATHS = frozenset({ROOT / "docs" / "research" / "raw"})
TEXT_SUFFIXES = frozenset(
    {
        ".cfg",
        ".css",
        ".html",
        ".ini",
        ".j2",
        ".jinja",
        ".js",
        ".json",
        ".md",
        ".ps1",
        ".py",
        ".pyi",
        ".sh",
        ".sql",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
    }
)
DASHES = {0x2013: "en dash", 0x2014: "em dash"}
EMOJI_RANGES = (
    (0x1F000, 0x1FAFF, "emoji"),
    (0x2600, 0x27BF, "symbol or dingbat"),
    (0x2B00, 0x2BFF, "symbol"),
    (0xFE00, 0xFE0F, "variation selector"),
    (0x200D, 0x200D, "zero width joiner"),
)


def describe(char: str) -> str | None:
    """Return why ``char`` is not allowed, or None if it is allowed."""
    code = ord(char)
    if code < 0x80:
        return None
    if code in DASHES:
        return DASHES[code]
    for low, high, label in EMOJI_RANGES:
        if low <= code <= high:
            return label
    return None


def iter_files(arguments: Sequence[str]) -> Iterator[Path]:
    """Yield the text files named by ``arguments`` (paths or root-relative globs)."""
    for argument in arguments:
        candidates = (
            sorted(ROOT.glob(argument)) if "*" in argument else [ROOT / argument]
        )
        for candidate in candidates:
            if candidate.is_file():
                yield candidate
            elif candidate.is_dir():
                yield from iter_dir(candidate)


def iter_dir(directory: Path) -> Iterator[Path]:
    """Yield text files below ``directory``, skipping caches and vendored folders."""
    for path in sorted(directory.iterdir()):
        if path.is_dir():
            if path.name not in SKIP_DIRS and path not in SKIP_PATHS:
                yield from iter_dir(path)
        elif path.suffix in TEXT_SUFFIXES:
            yield path


def check_file(path: Path) -> list[str]:
    """Return one problem line per disallowed character in ``path``."""
    relative = path.relative_to(ROOT).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{relative}: not valid UTF-8"]
    problems: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for column, char in enumerate(line, start=1):
            reason = describe(char)
            if reason is not None:
                problems.append(
                    f"{relative}:{number}:{column}: U+{ord(char):04X} {reason}"
                )
    return problems


def main(argv: list[str] | None = None) -> int:
    """Check the given paths and return the process exit code."""
    files = list(dict.fromkeys(iter_files(argv or DEFAULT_PATHS)))
    problems = [problem for path in files for problem in check_file(path)]
    for problem in problems:
        print(problem)
    if problems:
        print(
            f"check_text: {len(problems)} problem(s); use ASCII punctuation, no emoji"
        )
        return 1
    print(f"check_text: {len(files)} files OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
