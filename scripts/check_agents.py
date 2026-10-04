"""Check that AGENTS.md is the current copy of docs/plan/AGENT-RULES.md.

AGENTS.md is AGENT-RULES.md with a header comment and with every relative link
rewritten to work from the repository root. Usage::

    python scripts/check_agents.py          # exit 1 if AGENTS.md is out of date
    python scripts/check_agents.py --write  # regenerate AGENTS.md
"""

from __future__ import annotations

import difflib
import posixpath
import re
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "plan" / "AGENT-RULES.md"
TARGET = ROOT / "AGENTS.md"
SOURCE_DIR = "docs/plan"
HEADER = (
    "<!-- Generated from docs/plan/AGENT-RULES.md by"
    " scripts/check_agents.py --write. Edit the source, not this file. -->\n\n"
)
LINK = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def rewrite_target(target: str) -> str:
    """Return ``target`` as seen from the repository root."""
    if SCHEME.match(target) or target.startswith(("#", "/")):
        return target
    path, hash_sign, fragment = target.partition("#")
    joined = posixpath.normpath(posixpath.join(SOURCE_DIR, path))
    if path.endswith("/"):
        joined += "/"
    return joined + hash_sign + fragment


def rewrite_link(match: re.Match[str]) -> str:
    """Rewrite one Markdown link; link text that repeats the target follows it."""
    text, target = match.groups()
    new_target = rewrite_target(target)
    if text.strip("`") == target:
        text = text.replace(target, new_target)
    return f"[{text}]({new_target})"


def render() -> str:
    """Return the expected content of AGENTS.md."""
    source = SOURCE.read_text(encoding="utf-8")
    return HEADER + LINK.sub(rewrite_link, source)


def main(argv: Sequence[str] | None = None) -> int:
    """Check or regenerate AGENTS.md and return the exit code."""
    expected = render()
    if argv and list(argv) == ["--write"]:
        TARGET.write_text(expected, encoding="utf-8", newline="\n")
        print("check_agents: wrote AGENTS.md")
        return 0
    if argv:
        print("usage: python scripts/check_agents.py [--write]")
        return 2
    actual = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
    if actual == expected:
        print("check_agents: AGENTS.md matches docs/plan/AGENT-RULES.md")
        return 0
    diff = difflib.unified_diff(
        actual.splitlines(keepends=True),
        expected.splitlines(keepends=True),
        fromfile="AGENTS.md",
        tofile="AGENTS.md (expected)",
    )
    sys.stdout.writelines(diff)
    print(
        "check_agents: AGENTS.md is out of date with docs/plan/AGENT-RULES.md."
        " Run: ./dev.sh uv run python scripts/check_agents.py --write"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
