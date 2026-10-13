"""Output tests: the JSON snapshot and the SARIF 2.1.0 structure, field by field."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

import gotauth
from gotauth.checkup import RULES, format_sarif, main, scan

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOT = Path(__file__).parent / "snapshots" / "sample_app.json"
UPDATE_SNAPSHOTS = os.environ.get("GOTAUTH_UPDATE_SNAPSHOTS") == "1"


@pytest.fixture
def sample_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of the sample app plus two files that cannot be parsed, as the cwd."""
    root = tmp_path / "sample_app"
    shutil.copytree(FIXTURES / "sample_app", root)
    # Stored under another name so the repository's dependency graph does not
    # report the sample app's deliberately old pins (issue #27).
    (root / "requirements.txt.sample").rename(root / "requirements.txt")
    (root / "broken.py").write_text("def broken(:\n    pass\n")
    (root / "latin1.py").write_bytes(b"# caf\xe9\nimport passlib\n")
    monkeypatch.chdir(root)
    return root


def run_json(capsys: pytest.CaptureFixture[str], *argv: str) -> Any:
    assert main([*argv, "--json"]) == 0
    return json.loads(capsys.readouterr().out)


def test_json_output_matches_the_snapshot(
    sample_app: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = run_json(capsys)
    assert report["tool"]["version"] == gotauth.__version__
    # The tool version changes with every release, and the parser's wording of a
    # syntax error with the Python version; the snapshot pins the rest.
    report["tool"]["version"] = "<version>"
    for item in report["skipped"]:
        item["reason"] = item["reason"].split(":")[0]
    if UPDATE_SNAPSHOTS:
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(json.dumps(report, indent=2) + "\n")
    assert report == json.loads(SNAPSHOT.read_text())


def test_json_schema(sample_app: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = run_json(capsys)
    assert report["version"] == 1
    assert set(report) == {"version", "tool", "score", "summary", "findings", "skipped"}
    assert report["tool"]["name"] == "gotauth check"
    summary = report["summary"]
    assert summary["findings"] == len(report["findings"])
    assert summary["files_skipped"] == len(report["skipped"]) == 2
    assert summary["high"] + summary["medium"] + summary["low"] == summary["findings"]
    for finding in report["findings"]:
        assert set(finding) == {
            "rule_id",
            "severity",
            "path",
            "line",
            "column",
            "end_line",
            "end_column",
            "message",
            "hint",
            "help_uri",
            "fingerprint",
        }
        assert (
            finding["help_uri"]
            == f"https://gotauth.ablacky.com/check/{finding['rule_id']}"
        )
    assert {
        item["path"]: item["reason"].split(":")[0] for item in report["skipped"]
    } == {
        "broken.py": "syntax error at line 1",
        "latin1.py": "not valid UTF-8",
    }


# ---------------------------------------------------------------- SARIF

LEVELS = {"high": "error", "medium": "warning", "low": "note"}


def nonempty_text(value: object, limit: int | None = None) -> bool:
    return (
        isinstance(value, str)
        and value != ""
        and (limit is None or len(value) <= limit)
    )


@pytest.fixture
def sarif(sample_app: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    assert main(["--sarif"]) == 0
    return json.loads(capsys.readouterr().out)


def test_sarif_top_level(sarif: dict[str, Any]) -> None:
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert isinstance(sarif["runs"], list)
    assert len(sarif["runs"]) == 1


def test_sarif_tool_driver(sarif: dict[str, Any]) -> None:
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "gotauth check"
    assert driver["version"] == gotauth.__version__
    assert driver["semanticVersion"] == gotauth.__version__
    assert driver["informationUri"] == "https://gotauth.ablacky.com/check"
    rules = driver["rules"]
    assert [rule["id"] for rule in rules] == sorted(RULES)
    for rule in rules:
        source = RULES[rule["id"]]
        assert re.fullmatch(r"[A-Z][A-Za-z]+", rule["name"])
        assert nonempty_text(rule["shortDescription"]["text"], 1024)
        assert nonempty_text(rule["fullDescription"]["text"], 1024)
        assert nonempty_text(rule["help"]["text"])
        assert source.hint in rule["help"]["text"]
        assert rule["helpUri"] == f"https://gotauth.ablacky.com/check/{rule['id']}"
        assert rule["defaultConfiguration"]["level"] == LEVELS[source.severity]
        properties = rule["properties"]
        assert 0 < len(properties["tags"]) <= 20
        assert all(nonempty_text(tag) for tag in properties["tags"])
        assert properties["precision"] in {"very-high", "high", "medium", "low"}
        assert properties["problem.severity"] in {"error", "warning", "recommendation"}
        assert 0.1 <= float(properties["security-severity"]) <= 10.0


def test_sarif_results(sarif: dict[str, Any], sample_app: Path) -> None:
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert len(results) == len(scan(["."]).findings) > 0
    fingerprints: set[str] = set()
    for result in results:
        assert result["ruleId"] == rules[result["ruleIndex"]]["id"]
        assert result["level"] == LEVELS[RULES[result["ruleId"]].severity]
        assert nonempty_text(result["message"]["text"])
        assert len(result["locations"]) >= 1
        physical = result["locations"][0]["physicalLocation"]
        artifact = physical["artifactLocation"]
        assert nonempty_text(artifact["uri"])
        assert not artifact["uri"].startswith("/")
        assert "\\" not in artifact["uri"]
        assert (sample_app / artifact["uri"]).is_file()
        assert artifact["uriBaseId"] == "%SRCROOT%"
        region = physical["region"]
        assert region["startLine"] >= 1
        assert region["startColumn"] >= 1
        assert region["endLine"] >= region["startLine"]
        assert region["endColumn"] >= 1
        assert all(isinstance(region[key], int) for key in region)
        partial = result["partialFingerprints"]
        assert partial and all(nonempty_text(value) for value in partial.values())
        fingerprints.add(json.dumps(partial, sort_keys=True))
    assert len(fingerprints) == len(results)


def test_sarif_base_uri_and_skipped_files(
    sarif: dict[str, Any], sample_app: Path
) -> None:
    run = sarif["runs"][0]
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"] == sample_app.as_uri() + "/"
    (invocation,) = run["invocations"]
    assert invocation["executionSuccessful"] is True
    notifications = invocation["toolExecutionNotifications"]
    assert sorted(
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for item in notifications
    ) == ["broken.py", "latin1.py"]
    assert all(nonempty_text(item["message"]["text"]) for item in notifications)


def test_sarif_has_no_empty_strings(sarif: dict[str, Any]) -> None:
    def walk(value: object) -> None:
        if isinstance(value, dict):
            for item in value.values():  # pyright: ignore[reportUnknownVariableType]
                walk(item)  # pyright: ignore[reportUnknownArgumentType]
        elif isinstance(value, list):
            for item in value:  # pyright: ignore[reportUnknownVariableType]
                walk(item)  # pyright: ignore[reportUnknownArgumentType]
        else:
            assert value != ""

    walk(sarif)


def test_sarif_lists_only_selected_rules(sample_app: Path) -> None:
    log = json.loads(format_sarif(scan(["."], select=["GA001", "GA009"])))
    run = log["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["GA001", "GA009"]
    assert {result["ruleId"] for result in run["results"]} == {"GA001", "GA009"}


def test_sarif_uri_for_files_outside_the_working_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / "my app.py").write_text("import passlib\n")
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(tmp_path / "elsewhere")
    log = json.loads(format_sarif(scan([tmp_path / "project"])))
    artifact = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    assert artifact == {"uri": (tmp_path / "project" / "my app.py").as_uri()}
    monkeypatch.chdir(tmp_path)
    log = json.loads(format_sarif(scan(["project"])))
    artifact = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    assert artifact == {"uri": "project/my%20app.py", "uriBaseId": "%SRCROOT%"}
