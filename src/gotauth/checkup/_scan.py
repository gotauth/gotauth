"""File discovery, parsing, suppression comments and scoring for ``gotauth check``."""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import os
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from gotauth.checkup._rules import (
    MAX_COUNTED_PER_RULE,
    RULES,
    SEVERITY_WEIGHTS,
    Rule,
    Severity,
    resolve_rule_ids,
)
from gotauth.checkup._visitor import RawFinding, analyze

__all__ = [
    "DEFAULT_SKIP_DIRS",
    "Finding",
    "Report",
    "SkippedFile",
    "scan",
    "scan_source",
    "score",
]

DEFAULT_SKIP_DIRS: Final = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "venv",
    }
)
"""Folder names never entered while walking. Hidden folders (``.tox``, ``.nox``, ...)
and virtual environments (folders with a ``pyvenv.cfg``) are skipped too."""

MAX_FILE_BYTES: Final = 5 * 1024 * 1024
"""Larger files are skipped: they are generated code, not hand-written auth."""

# GA007 stays quiet when the project uses one of these (module names and package
# names as they appear in dependency files).
_RATE_LIMIT_MODULES: Final = (
    "django_ratelimit",
    "fastapi_limiter",
    "flask_limiter",
    "gotauth",
    "limits",
    "litestar.middleware.rate_limit",
    "slowapi",
)
_RATE_LIMIT_PACKAGES: Final = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(slowapi|limits|fastapi[-_.]limiter|flask[-_.]limiter|django[-_.]ratelimit|gotauth)"
    r"(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_DEPENDENCY_FILES: Final = frozenset(
    {
        "Pipfile",
        "Pipfile.lock",
        "pdm.lock",
        "poetry.lock",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "uv.lock",
    }
)

_SUPPRESSION: Final = re.compile(r"#\s*gotauth:\s*ignore\[([A-Za-z0-9_,\s]+)\]")
_LINE_BREAK: Final = re.compile(r"\r\n|\r|\n")


@dataclass(frozen=True, slots=True)
class Finding:
    """One problem found in one file.

    Attributes:
        rule_id: The rule that found it, for example ``"GA003"``.
        severity: ``"high"``, ``"medium"`` or ``"low"``.
        path: The file, relative to the working directory when it is inside it,
            with ``/`` separators.
        line: First line, starting at 1.
        column: First column, starting at 1, counted in characters.
        end_line: Last line.
        end_column: Column just after the end, starting at 1 (as in SARIF).
        message: What is wrong at this place.
        hint: How to fix it.
        fingerprint: A stable id of the finding that survives unrelated edits: a hash
            of the rule id and the text of the line, plus a counter for repeats in
            the same file.
    """

    rule_id: str
    severity: Severity
    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    message: str
    hint: str
    fingerprint: str = field(default="", compare=False)

    @property
    def location(self) -> str:
        """``path:line:column``."""
        return f"{self.path}:{self.line}:{self.column}"

    @property
    def help_uri(self) -> str:
        """The documentation page of the rule."""
        return RULES[self.rule_id].help_uri


@dataclass(frozen=True, slots=True)
class SkippedFile:
    """A file that could not be scanned.

    Attributes:
        path: The file, written like :attr:`Finding.path`.
        reason: Why it was skipped, for example ``"not valid UTF-8"``.
    """

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class Report:
    """The result of a scan.

    Attributes:
        findings: Every finding, sorted by path, line and column.
        skipped: Files that could not be parsed or read.
        files_scanned: How many Python files were parsed.
        rules: The rules that ran.
    """

    findings: tuple[Finding, ...]
    skipped: tuple[SkippedFile, ...]
    files_scanned: int
    rules: tuple[Rule, ...]

    @property
    def score(self) -> int:
        """The score from 0 to 100, see :func:`score`."""
        return score(self.findings)

    def count(self, severity: Severity) -> int:
        """Return how many findings have ``severity``."""
        return sum(1 for finding in self.findings if finding.severity == severity)


def score(findings: Iterable[Finding]) -> int:
    """Return the score from 0 to 100 for a list of findings.

    Every finding takes points off 100: high 15, medium 6, low 2. Only the first
    three findings of each rule count, so one repeated pattern cannot dominate the
    score. The score never goes below 0.

    Args:
        findings: The findings.

    Returns:
        The score.
    """
    weights: dict[str, list[int]] = {}
    for finding in findings:
        weights.setdefault(finding.rule_id, []).append(
            SEVERITY_WEIGHTS[finding.severity]
        )
    penalty = sum(
        sum(sorted(rule_weights, reverse=True)[:MAX_COUNTED_PER_RULE])
        for rule_weights in weights.values()
    )
    return max(0, 100 - penalty)


# ---------------------------------------------------------------------------- one file


@dataclass(slots=True)
class _FileResult:
    findings: list[Finding]
    imports: set[str]


def _char_column(line: str, byte_offset: int) -> int:
    """Turn an ``ast`` column (UTF-8 bytes) into a character count."""
    if line.isascii():
        return byte_offset
    return len(line.encode("utf-8")[:byte_offset].decode("utf-8", "ignore"))


def _suppressed(line: str) -> frozenset[str]:
    match = _SUPPRESSION.search(line)
    if match is None:
        return frozenset()
    return frozenset(
        part.strip().upper() for part in match.group(1).split(",") if part.strip()
    )


def _finish(raw: list[RawFinding], text: str, path: str) -> list[Finding]:
    if not raw:
        return []
    lines = _LINE_BREAK.split(text)
    may_suppress = "gotauth" in text
    findings: list[Finding] = []
    repeats: dict[str, int] = {}
    for item in raw:
        line_text = lines[item.line - 1] if item.line <= len(lines) else ""
        if may_suppress and item.rule_id in _suppressed(line_text):
            continue
        end_text = lines[item.end_line - 1] if item.end_line <= len(lines) else ""
        digest = hashlib.sha256(
            f"{item.rule_id}\0{' '.join(line_text.split())}".encode()
        ).hexdigest()[:16]
        repeats[digest] = repeats.get(digest, 0) + 1
        rule = RULES[item.rule_id]
        findings.append(
            Finding(
                rule_id=item.rule_id,
                severity=rule.severity,
                path=path,
                line=item.line,
                column=_char_column(line_text, item.col) + 1,
                end_line=item.end_line,
                end_column=_char_column(end_text, item.end_col) + 1,
                message=item.message,
                hint=rule.hint,
                fingerprint=f"{digest}:{repeats[digest]}",
            )
        )
    return findings


def _scan_bytes(
    data: bytes, path: str, enabled: frozenset[str]
) -> _FileResult | SkippedFile:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return SkippedFile(path, "not valid UTF-8")
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as error:
        where = f" at line {error.lineno}" if error.lineno else ""
        return SkippedFile(path, f"syntax error{where}: {error.msg}")
    except ValueError as error:  # null bytes on Python 3.11
        return SkippedFile(path, f"cannot be parsed: {error}")
    except RecursionError:
        return SkippedFile(path, "too deeply nested to parse")
    try:
        facts = analyze(tree, enabled)
    except RecursionError:
        return SkippedFile(path, "too deeply nested to analyze")
    return _FileResult(_finish(facts.findings, text, path), facts.imports)


def scan_source(
    source: str | bytes,
    path: str = "<source>",
    *,
    select: Iterable[str] | None = None,
    ignore: Iterable[str] = (),
) -> list[Finding]:
    """Scan one piece of source code.

    The source counts as the whole project, so GA007 stays quiet only when this
    source itself imports a rate limiter.

    Args:
        source: Python source code. Bytes must be UTF-8.
        path: The name to report in findings.
        select: Rule ids to run (default: all).
        ignore: Rule ids to leave out.

    Returns:
        The findings, sorted by position.

    Raises:
        ValueError: If a rule id is unknown, or the source cannot be parsed.
    """
    enabled = resolve_rule_ids(select, ignore)
    data = source.encode("utf-8") if isinstance(source, str) else source
    result = _scan_bytes(data, path, enabled)
    if isinstance(result, SkippedFile):
        raise ValueError(f"{result.path}: {result.reason}")
    if _has_rate_limiter(result.imports):
        return [item for item in result.findings if item.rule_id != "GA007"]
    return result.findings


# ---------------------------------------------------------------------------- discovery


@dataclass(slots=True)
class _Walk:
    sources: list[tuple[Path, str]] = field(
        default_factory=lambda: list[tuple[Path, str]]()
    )
    dependency_files: list[Path] = field(default_factory=lambda: list[Path]())
    seen: set[str] = field(default_factory=lambda: set[str]())


def _display_root(path: Path, cwd: Path) -> str:
    absolute = path.absolute()
    try:
        relative = Path(os.path.relpath(absolute, cwd))
    except ValueError:  # another drive on Windows
        return absolute.as_posix()
    if relative.parts and relative.parts[0] == "..":
        return absolute.as_posix()
    return relative.as_posix()


def _join(root: str, relative: str) -> str:
    return relative if root == "." else f"{root}/{relative}"


def _normalize_globs(globs: Iterable[str]) -> tuple[str, ...]:
    patterns: list[str] = []
    for glob in globs:
        cleaned = glob.replace("\\", "/").rstrip("/")
        if cleaned.startswith("./"):
            cleaned = cleaned[2:]
        if cleaned:
            patterns.append(cleaned)
            if cleaned.startswith("**/"):
                patterns.append(cleaned[3:])
    return tuple(patterns)


def _excluded(globs: Sequence[str], *candidates: str) -> bool:
    return any(
        fnmatch.fnmatch(candidate, glob) for glob in globs for candidate in candidates
    )


def _is_dependency_file(name: str, parent: str) -> bool:
    if name in _DEPENDENCY_FILES:
        return True
    suffix = os.path.splitext(name)[1]
    return suffix in (".txt", ".in") and (
        name.startswith("requirements") or parent == "requirements"
    )


def _add_file(walk: _Walk, path: Path, display: str) -> None:
    key = os.path.normcase(os.path.abspath(path))
    if key in walk.seen:
        return
    walk.seen.add(key)
    if path.suffix == ".py":
        walk.sources.append((path, display))
    if _is_dependency_file(path.name, path.parent.name):
        walk.dependency_files.append(path)


def _skip_dir(directory: Path, name: str) -> bool:
    return (
        name in DEFAULT_SKIP_DIRS
        or name.startswith(".")
        or name.endswith(".egg-info")
        or (directory / name / "pyvenv.cfg").is_file()
    )


def _walk_dir(walk: _Walk, root: Path, display: str, globs: Sequence[str]) -> None:
    for current, dirnames, filenames in os.walk(root):
        current_path = Path(current)
        relative_dir = current_path.relative_to(root).as_posix()
        prefix = "" if relative_dir == "." else relative_dir + "/"
        kept: list[str] = []
        for name in sorted(dirnames):
            relative = prefix + name
            if _skip_dir(current_path, name) or _excluded(
                globs, relative, _join(display, relative), name
            ):
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            relative = prefix + name
            if not (
                name.endswith(".py") or _is_dependency_file(name, current_path.name)
            ):
                continue
            if _excluded(globs, relative, _join(display, relative), name):
                continue
            _add_file(walk, current_path / name, _join(display, relative))


def _discover(
    roots: Sequence[str | os.PathLike[str]], globs: Sequence[str], cwd: Path
) -> _Walk:
    walk = _Walk()
    for root in roots:
        path = Path(root)
        display = _display_root(path, cwd)
        if path.is_dir():
            _walk_dir(walk, path, display, globs)
        elif path.is_file() and not _excluded(globs, display, path.name):
            # An explicit file is scanned as Python whatever its suffix.
            key = os.path.normcase(os.path.abspath(path))
            if key not in walk.seen:
                walk.seen.add(key)
                if _is_dependency_file(path.name, path.parent.name):
                    walk.dependency_files.append(path)
                else:
                    walk.sources.append((path, display))
    return walk


# ---------------------------------------------------------------------------- project


def _has_rate_limiter(imports: Iterable[str]) -> bool:
    return any(
        name == module or name.startswith(module + ".")
        for name in imports
        for module in _RATE_LIMIT_MODULES
    )


def _dependency_files_mention_limiter(paths: Iterable[Path]) -> bool:
    for path in paths:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text("utf-8", errors="replace")
        except OSError:
            continue
        if _RATE_LIMIT_PACKAGES.search(text):
            return True
    return False


def _read(path: Path, display: str) -> bytes | SkippedFile:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        return SkippedFile(display, f"cannot be read: {error.strerror or error}")
    if len(data) > MAX_FILE_BYTES:
        return SkippedFile(display, f"larger than {MAX_FILE_BYTES // 1024 // 1024} MiB")
    return data


def _iter_results(
    sources: Iterable[tuple[Path, str]], enabled: frozenset[str]
) -> Iterator[_FileResult | SkippedFile]:
    for path, display in sources:
        data = _read(path, display)
        if isinstance(data, SkippedFile):
            yield data
        else:
            yield _scan_bytes(data, display, enabled)


def scan(
    paths: Iterable[str | os.PathLike[str]] = (".",),
    *,
    select: Iterable[str] | None = None,
    ignore: Iterable[str] = (),
    exclude: Iterable[str] = (),
    cwd: str | os.PathLike[str] | None = None,
) -> Report:
    """Scan files and folders for risky auth code.

    Folders are walked recursively for ``*.py`` files, leaving out
    :data:`DEFAULT_SKIP_DIRS`, hidden folders and virtual environments. Files are only
    read and parsed, never imported or run.

    Args:
        paths: Files and folders to scan.
        select: Rule ids to run (default: all).
        ignore: Rule ids to leave out.
        exclude: Glob patterns of files and folders to leave out. A pattern matches
            the path relative to the scanned folder, the path as reported, or the
            bare file or folder name.
        cwd: The folder reported paths are relative to (default: the current
            working directory).

    Returns:
        The report.

    Raises:
        ValueError: If a rule id is unknown.
    """
    enabled = resolve_rule_ids(select, ignore)
    base = Path(cwd).absolute() if cwd is not None else Path.cwd()
    walk = _discover(list(paths), _normalize_globs(exclude), base)
    findings: list[Finding] = []
    skipped: list[SkippedFile] = []
    imports: set[str] = set()
    scanned = 0
    for result in _iter_results(
        sorted(walk.sources, key=lambda item: item[1]), enabled
    ):
        if isinstance(result, SkippedFile):
            skipped.append(result)
            continue
        scanned += 1
        findings.extend(result.findings)
        imports |= result.imports
    if any(item.rule_id == "GA007" for item in findings) and (
        _has_rate_limiter(imports)
        or _dependency_files_mention_limiter(walk.dependency_files)
    ):
        findings = [item for item in findings if item.rule_id != "GA007"]
    findings.sort(key=lambda item: (item.path, item.line, item.column, item.rule_id))
    return Report(
        findings=tuple(findings),
        skipped=tuple(skipped),
        files_scanned=scanned,
        rules=tuple(rule for rule_id, rule in RULES.items() if rule_id in enabled),
    )
