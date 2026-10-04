"""Command line tests: options, exit codes, text output and ``python -m``."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import gotauth
from gotauth.checkup import main, scan

FIXTURES = Path(__file__).parent / "fixtures"
SCORE70 = FIXTURES / "score70"


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_fixture_scores_70() -> None:
    assert scan([SCORE70]).score == 70


def test_fail_under_above_the_score_exits_1(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, str(SCORE70), "--fail-under", "90")
    assert code == 1
    assert out.endswith("Score: 70/100\n")


@pytest.mark.parametrize("threshold", ["70", "0"])
def test_fail_under_at_or_below_the_score_exits_0(
    capsys: pytest.CaptureFixture[str], threshold: str
) -> None:
    code, _, _ = run(capsys, str(SCORE70), "--fail-under", threshold)
    assert code == 0


def test_findings_alone_do_not_fail(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, _ = run(capsys, str(SCORE70))
    assert code == 0


@pytest.mark.parametrize(
    "argv",
    [
        ["--fail-under", "101"],
        ["--fail-under", "-1"],
        ["--fail-under", "high"],
        ["--json", "--sarif"],
        ["--select", "GA999"],
        ["--ignore", "GA001,XX"],
        ["--no-such-option"],
        ["does/not/exist"],
    ],
)
def test_usage_errors_exit_2(
    capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    code, out, err = run(capsys, *argv)
    assert code == 2
    assert out == ""
    assert "usage: gotauth check" in err


def test_help_and_version_exit_0(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "--help")
    assert code == 0
    assert "--fail-under" in out
    code, out, _ = run(capsys, "--version")
    assert code == 0
    assert out.strip() == f"gotauth check {gotauth.__version__}"


def test_default_path_is_the_current_folder(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(SCORE70)
    code, out, _ = run(capsys, "--json")
    assert code == 0
    report = json.loads(out)
    assert report["score"] == 70
    assert {item["path"] for item in report["findings"]} == {"app.py"}


def test_select_and_ignore_change_the_score(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, str(SCORE70), "--json", "--select", "GA008")
    assert json.loads(out)["score"] == 85
    _, out, _ = run(
        capsys, str(SCORE70), "--json", "--ignore", "ga008", "--ignore", "GA013"
    )
    assert json.loads(out)["score"] == 100


def test_exclude(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("import passlib\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("import jose\n")
    (tmp_path / "app" / "main_test.py").write_text("import jose\n")
    _, out, _ = run(
        capsys, str(tmp_path), "--json", "--exclude", "tests", "--exclude", "*_test.py"
    )
    report = json.loads(out)
    assert [item["rule_id"] for item in report["findings"]] == ["GA001"]
    assert report["summary"]["files_scanned"] == 1


def test_default_skips(tmp_path: Path) -> None:
    for folder in [
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "site-packages",
        "build",
        "dist",
        ".tox",
        "pkg.egg-info",
    ]:
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "bad.py").write_text("import passlib\n")
    (tmp_path / "env").mkdir()
    (tmp_path / "env" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (tmp_path / "env" / "bad.py").write_text("import passlib\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.py").write_text("x = 1\n")
    report = scan([tmp_path])
    assert report.findings == ()
    assert report.files_scanned == 1
    # Folders named explicitly are scanned even when the walk would skip them.
    assert len(scan([tmp_path / "build"]).findings) == 1


def test_overlapping_paths_are_scanned_once(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import passlib\n")
    report = scan([tmp_path, tmp_path / "app.py", tmp_path])
    assert report.files_scanned == 1
    assert len(report.findings) == 1


def test_paths_outside_the_working_folder_are_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / "app.py").write_text("import passlib\n")
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(tmp_path / "elsewhere")
    (finding,) = scan([tmp_path / "project"]).findings
    assert finding.path == (tmp_path / "project" / "app.py").absolute().as_posix()
    monkeypatch.chdir(tmp_path)
    (finding,) = scan(["project"]).findings
    assert finding.path == "project/app.py"


def test_text_output_groups_by_file_and_ends_with_the_score(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(FIXTURES)
    code, out, _ = run(capsys, "GA001", "score70")
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == "GA001/positive.py"
    assert lines[1].startswith("  5:1  high    GA001  passlib is imported;")
    assert lines[2].strip().startswith("fix: Hash new passwords")
    assert "score70/app.py" in lines
    assert lines[-2] == "Scanned 3 files: 3 findings (3 high, 0 medium, 0 low)."
    assert lines[-1] == "Score: 55/100"


def test_text_output_without_findings(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, str(FIXTURES / "GA001" / "negative.py"))
    assert code == 0
    assert out == "Scanned 1 file: no findings.\nScore: 100/100\n"


def test_python_dash_m() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "gotauth.checkup", str(SCORE70), "--fail-under", "90"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout.endswith("Score: 70/100\n")
    assert result.stderr == ""
