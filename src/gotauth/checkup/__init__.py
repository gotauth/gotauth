"""``gotauth check``: a static scanner for risky hand-written Python auth code.

It parses Python files with :mod:`ast`, never imports or runs them, needs only the
standard library, and gives a score from 0 to 100::

    from gotauth.checkup import scan

    report = scan(["src"])
    for finding in report.findings:
        print(finding.location, finding.rule_id, finding.message)
    print(report.score)

On the command line: ``gotauth check [PATHS...]`` or ``python -m gotauth.checkup``.
"""

from __future__ import annotations

from gotauth.checkup._cli import main
from gotauth.checkup._output import format_json, format_sarif, format_text
from gotauth.checkup._rules import RULES, Rule, Severity
from gotauth.checkup._scan import Finding, Report, SkippedFile, scan, scan_source, score

__all__ = [
    "RULES",
    "Finding",
    "Report",
    "Rule",
    "Severity",
    "SkippedFile",
    "format_json",
    "format_sarif",
    "format_text",
    "main",
    "scan",
    "scan_source",
    "score",
]
