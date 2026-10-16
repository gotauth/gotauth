"""report.py counts only what it measured (Q2)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from report import main

DIFF = """\
+++ b/app/main.py
+from gotauth import GotAuth
+
+# a comment
+auth = GotAuth(...)
+++ b/tests/test_app.py
+def test_x() -> None: ...
+++ b/pyproject.toml
+  "gotauth[fastapi,sqlalchemy,sqlite]",
"""


def test_report(tmp_path: Path) -> None:
    run = tmp_path / "run-1"
    run.mkdir()
    (run / "check.json").write_text(
        json.dumps([{"name": "x", "passed": True, "detail": ""}])
    )
    (run / "diff.patch").write_text(DIFF)
    (run / "transcript.jsonl").write_text(
        json.dumps({"type": "system", "model": "claude-test"}) + "\n"
    )
    out = tmp_path / "baseline.md"
    assert (
        main(
            [
                str(tmp_path),
                "--cli-version",
                "2.1.287",
                "--mode",
                "baseline",
                "--write",
                str(out),
            ]
        )
        == 0
    )
    text = out.read_text()
    assert "1 of 1 runs passed" in text
    assert "| run-1 | pass | 2 | `gotauth[fastapi,sqlalchemy,sqlite]` |" in text
    assert "model claude-test" in text and "without GotAuth's skill" in text
    assert "'Add email + password and GitHub login" in text
