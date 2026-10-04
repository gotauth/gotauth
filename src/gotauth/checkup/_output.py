"""Text, JSON and SARIF output for ``gotauth check``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final
from urllib.parse import quote

from gotauth import __version__
from gotauth.checkup._rules import RULES, Rule, Severity
from gotauth.checkup._scan import Finding, Report

__all__ = [
    "JSON_SCHEMA_VERSION",
    "SARIF_SCHEMA",
    "TOOL_NAME",
    "format_json",
    "format_sarif",
    "format_text",
]

TOOL_NAME: Final = "gotauth check"
INFORMATION_URI: Final = "https://gotauth.dev/check"
JSON_SCHEMA_VERSION: Final = 1
"""Version of the ``--json`` output. It changes only when a field changes meaning or
goes away; new fields may appear without a bump."""

SARIF_SCHEMA: Final = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_LEVEL: Final[dict[Severity, str]] = {
    "high": "error",
    "medium": "warning",
    "low": "note",
}
# GitHub code scanning maps security-severity to its labels: 7.0 to 8.9 is "high",
# 4.0 to 6.9 "medium", 0.1 to 3.9 "low".
_SECURITY_SEVERITY: Final[dict[Severity, str]] = {
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
}
_PROBLEM_SEVERITY: Final[dict[Severity, str]] = {
    "high": "error",
    "medium": "warning",
    "low": "recommendation",
}
_SRCROOT: Final = "%SRCROOT%"

_JsonObject = dict[str, object]


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


# ---------------------------------------------------------------------------- text


def format_text(report: Report) -> str:
    """Render a report for a terminal: findings grouped by file, score last.

    Args:
        report: The scan result.

    Returns:
        The text, ending with a newline.
    """
    lines: list[str] = []
    groups: dict[str, list[Finding]] = {}
    for finding in report.findings:
        groups.setdefault(finding.path, []).append(finding)
    for path, findings in groups.items():
        lines.append(path)
        width = max(len(f"{item.line}:{item.column}") for item in findings)
        for item in findings:
            position = f"{item.line}:{item.column}".ljust(width)
            prefix = f"  {position}  {item.severity:<6}  {item.rule_id}  "
            lines.append(prefix + item.message)
            lines.append(" " * len(prefix) + "fix: " + item.hint)
        lines.append("")
    if report.skipped:
        lines.append(f"Skipped {_plural(len(report.skipped), 'file')}:")
        lines.extend(f"  {item.path}: {item.reason}" for item in report.skipped)
        lines.append("")
    scanned = f"Scanned {_plural(report.files_scanned, 'file')}"
    if report.findings:
        counts = ", ".join(
            f"{report.count(severity)} {severity}"
            for severity in ("high", "medium", "low")
        )
        lines.append(
            f"{scanned}: {_plural(len(report.findings), 'finding')} ({counts})."
        )
    else:
        lines.append(f"{scanned}: no findings.")
    lines.append(f"Score: {report.score}/100")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------- JSON


def _json_report(report: Report) -> _JsonObject:
    return {
        "version": JSON_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "score": report.score,
        "summary": {
            "files_scanned": report.files_scanned,
            "files_skipped": len(report.skipped),
            "findings": len(report.findings),
            "high": report.count("high"),
            "medium": report.count("medium"),
            "low": report.count("low"),
        },
        "findings": [
            {
                "rule_id": item.rule_id,
                "severity": item.severity,
                "path": item.path,
                "line": item.line,
                "column": item.column,
                "end_line": item.end_line,
                "end_column": item.end_column,
                "message": item.message,
                "hint": item.hint,
                "help_uri": item.help_uri,
                "fingerprint": item.fingerprint,
            }
            for item in report.findings
        ],
        "skipped": [
            {"path": item.path, "reason": item.reason} for item in report.skipped
        ],
    }


def format_json(report: Report) -> str:
    """Render a report as JSON.

    The top-level object has ``version`` (the schema version, currently 1),
    ``tool``, ``score``, ``summary``, ``findings`` and ``skipped``. Columns start at
    1 and ``end_column`` points just after the end, as in SARIF.

    Args:
        report: The scan result.

    Returns:
        The JSON text, ending with a newline.
    """
    return json.dumps(_json_report(report), indent=2) + "\n"


# ---------------------------------------------------------------------------- SARIF


def _sarif_rule(rule: Rule) -> _JsonObject:
    return {
        "id": rule.id,
        "name": "".join(part.capitalize() for part in rule.name.split("-")),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {
            "text": f"{rule.description}\n\nFix: {rule.hint}",
            "markdown": f"{rule.description}\n\n**Fix:** {rule.hint}",
        },
        "helpUri": rule.help_uri,
        "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", "authentication"],
            "precision": rule.precision,
            "problem.severity": _PROBLEM_SEVERITY[rule.severity],
            "security-severity": _SECURITY_SEVERITY[rule.severity],
        },
    }


def _artifact_location(path: str) -> _JsonObject:
    candidate = Path(path)
    if candidate.is_absolute():  # a file outside the working directory
        return {"uri": candidate.as_uri()}
    return {"uri": quote(path), "uriBaseId": _SRCROOT}


def _sarif_result(finding: Finding, rule_index: int) -> _JsonObject:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": _artifact_location(finding.path),
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                        "endLine": finding.end_line,
                        "endColumn": finding.end_column,
                    },
                }
            }
        ],
        "partialFingerprints": {"gotauthCheck/v1": finding.fingerprint},
    }


def format_sarif(report: Report, *, root: Path | None = None) -> str:
    """Render a report as SARIF 2.1.0 for GitHub code scanning.

    Relative paths are resolved against ``%SRCROOT%``, which ``originalUriBaseIds``
    maps to ``root``.

    Args:
        report: The scan result.
        root: The folder the relative paths start from (default: the current
            working directory).

    Returns:
        The SARIF log as JSON text, ending with a newline.
    """
    rules = report.rules or tuple(RULES[item.rule_id] for item in report.findings)
    rule_index = {rule.id: index for index, rule in enumerate(rules)}
    base = (root or Path.cwd()).absolute().as_uri().rstrip("/") + "/"
    run: _JsonObject = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "rules": [_sarif_rule(rule) for rule in rules],
            }
        },
        "originalUriBaseIds": {_SRCROOT: {"uri": base}},
        "invocations": [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {
                        "level": "warning",
                        "message": {"text": f"Skipped {item.path}: {item.reason}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": _artifact_location(item.path)
                                }
                            }
                        ],
                    }
                    for item in report.skipped
                ],
            }
        ],
        "results": [
            _sarif_result(item, rule_index[item.rule_id]) for item in report.findings
        ],
    }
    log: _JsonObject = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(log, indent=2) + "\n"
