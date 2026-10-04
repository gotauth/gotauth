"""Fail on en dashes, em dashes and emoji in the repository's text files.

Usage::

    python scripts/check_text.py [PATH ...]

Without arguments it checks every text file in the repository: the files git lists
(tracked, plus untracked files that are not ignored) when git works, otherwise a walk
of the working tree. That fallback matters in the dev container, which has no git.
Dependency folders, caches, build output, lockfiles and ``docs/research/raw``
(verbatim third-party snapshots) are skipped. With arguments it checks those files and
folders, relative to the repository root.

AGENT-RULES section 5 asks for plain ASCII punctuation and no emoji. Tests that need
such characters as data use escapes, for example ``"\\u2014"``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = frozenset(
    {
        ".astro",
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".turbo",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site",
    }
)
# Verbatim third-party snapshots kept as research evidence (work package R1).
SKIP_PREFIXES = ("docs/research/raw/",)
LOCKFILES = frozenset(
    {"package-lock.json", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "yarn.lock"}
)
TEXT_SUFFIXES = frozenset(
    {
        ".astro",
        ".cfg",
        ".cjs",
        ".css",
        ".dockerfile",
        ".htm",
        ".html",
        ".ini",
        ".j2",
        ".jinja",
        ".js",
        ".json",
        ".jsonc",
        ".jsx",
        ".md",
        ".mdx",
        ".mjs",
        ".mts",
        ".ps1",
        ".py",
        ".pyi",
        ".scss",
        ".sh",
        ".sql",
        ".svg",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
TEXT_NAMES = frozenset(
    {
        ".editorconfig",
        ".env.example",
        ".gitattributes",
        ".gitignore",
        ".node-version",
        ".npmrc",
        ".nvmrc",
        ".python-version",
        "Dockerfile",
        "LICENSE",
        "Makefile",
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


def is_skipped_dir(relative: PurePosixPath) -> bool:
    """Return True for a folder this check never enters."""
    return relative.name in SKIP_DIRS or (relative.as_posix() + "/").startswith(
        SKIP_PREFIXES
    )


def is_skipped(relative: PurePosixPath) -> bool:
    """Return True for files inside skipped folders and for lockfiles."""
    if any(is_skipped_dir(parent) for parent in relative.parents):
        return True
    return relative.name in LOCKFILES or relative.suffix == ".lock"


def is_text(relative: PurePosixPath) -> bool:
    """Return True for files this check reads, judged by name or suffix."""
    return relative.name in TEXT_NAMES or relative.suffix.lower() in TEXT_SUFFIXES


def git_files() -> list[PurePosixPath] | None:
    """Return the files git knows about, or None when git is not usable here."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        # Fixed arguments, no user input.
        result = subprocess.run(  # noqa: S603
            [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    names = result.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [PurePosixPath(name) for name in names if name]


def walk_files(start: Path) -> Iterator[PurePosixPath]:
    """Yield the files below ``start``, pruning skipped folders."""
    for directory, dirnames, filenames in os.walk(start):
        relative_dir = PurePosixPath(Path(directory).relative_to(ROOT).as_posix())
        dirnames[:] = sorted(
            name for name in dirnames if not is_skipped_dir(relative_dir / name)
        )
        for name in sorted(filenames):
            yield relative_dir / name


def default_files() -> Iterable[PurePosixPath]:
    """Return the repository's files, from git when possible."""
    files = git_files()
    return files if files is not None else walk_files(ROOT)


def argument_files(arguments: Sequence[str]) -> Iterator[PurePosixPath]:
    """Yield the files named by ``arguments`` (files or folders)."""
    for argument in arguments:
        path = (ROOT / argument).resolve()
        if path.is_dir():
            yield from walk_files(path)
        elif path.is_file():
            yield PurePosixPath(path.relative_to(ROOT).as_posix())


def check_file(relative: PurePosixPath) -> list[str]:
    """Return one problem line per disallowed character in the file."""
    data = (ROOT / relative).read_bytes()
    if b"\0" in data:
        return []  # binary
    try:
        text = data.decode("utf-8")
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


def main(argv: Sequence[str] | None = None) -> int:
    """Check the given paths, or the whole repository, and return the exit code."""
    candidates = argument_files(argv) if argv else default_files()
    files = sorted(
        {
            relative
            for relative in candidates
            if not is_skipped(relative)
            and is_text(relative)
            and (ROOT / relative).is_file()
        }
    )
    problems = [problem for relative in files for problem in check_file(relative)]
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
