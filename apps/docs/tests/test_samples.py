"""Every code sample in the hand-written docs pages and the agent skill runs here.

A ```python block runs as is, in one namespace per page, in a fresh directory with
``GOTAUTH_SECRET`` set. A marker comment on the line before a block changes that:

- ``<!-- sample: file=auth.py -->`` writes the block to that file instead (later blocks
  import it)
- ``<!-- sample: run -->`` on a ```bash block runs its ``gotauth ...`` lines with
  the CLI
- ``<!-- sample: skip: <reason> -->`` skips the block; the reason is required

Shell blocks without ``run`` are not executed. Pages built from the module READMEs
(hooks.py) are not checked here: each work package owns its README, and their snippets
are fragments of a larger app on purpose.
"""

from __future__ import annotations

import re
import sys
import textwrap
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1] / "docs"
ROOT = Path(__file__).resolve().parents[3]
SOURCES = [*sorted(DOCS.rglob("*.md")), ROOT / "skills" / "gotauth" / "SKILL.md"]

# Fences may be indented (inside admonitions and tabs); the marker sits on the line
# before, with any indent.
_BLOCK = re.compile(
    r"(?:^[ \t]*<!-- sample: (?P<marker>.*?) -->\n)?"
    r"^(?P<indent>[ \t]*)```(?P<lang>[a-z]*)\n(?P<code>.*?)^(?P=indent)```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)


@dataclass(frozen=True)
class Block:
    lang: str
    marker: str
    code: str
    line: int


def blocks(path: Path) -> Iterator[Block]:
    text = path.read_text(encoding="utf-8")
    for match in _BLOCK.finditer(text):
        yield Block(
            lang=match.group("lang"),
            marker=(match.group("marker") or "").strip(),
            code=textwrap.dedent(match.group("code")),
            line=text.count("\n", 0, match.start()) + 1,
        )


def _name(path: Path) -> str:
    return str(path.relative_to(ROOT))


@pytest.mark.parametrize("path", SOURCES, ids=_name)
def test_samples_run(
    path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gotauth.cli import main as cli

    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv("GOTAUTH_SECRET", "docs-samples-secret-" + "x" * 32)
    # The samples' defaults (a SQLite file here, localhost), whatever the caller set.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("BASE_URL", raising=False)
    written: list[str] = []
    namespace: dict[str, object] = {"__name__": "__docs_sample__"}
    try:
        for block in blocks(path):
            where = f"{_name(path)}:{block.line}"
            if block.marker.startswith("skip"):
                reason = block.marker.partition(":")[2].strip()
                assert reason, f"{where}: a skipped sample needs a reason"
                continue
            if block.lang == "python":
                if block.marker.startswith("file="):
                    target = tmp_path / block.marker.removeprefix("file=")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(block.code, encoding="utf-8")
                    written.append(target.stem)
                    continue
                assert block.marker in ("", "run"), f"{where}: unknown marker"
                exec(compile(block.code, where, "exec"), namespace)  # noqa: S102
            elif block.lang == "bash" and block.marker == "run":
                for line in block.code.splitlines():
                    if line.startswith("gotauth "):
                        code = cli(line.split()[1:])
                        assert code == 0, f"{where}: `{line}` exited with {code}"
    finally:
        # The next page writes its own auth.py and main.py.
        for module in written:
            sys.modules.pop(module, None)


def test_every_page_has_a_sample_rule() -> None:
    """Python blocks run unless a marker says otherwise, so nothing slips through."""
    for path in SOURCES:
        for block in blocks(path):
            if block.lang == "python":
                assert (
                    block.marker == ""
                    or block.marker == "run"
                    or block.marker.startswith(("file=", "skip:"))
                ), f"{_name(path)}:{block.line}: unknown marker {block.marker!r}"
